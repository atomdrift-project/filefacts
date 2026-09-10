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
/// then `id`/`size` chunks. Used by `.wav`, `.webp` and `.avi`.
pub(crate) fn riff(bytes: &[u8]) -> Coverage {
    let Some(head) = bytes.get(..12) else {
        let mut c = Coverage::unrecognized();
        c.problem("header truncated");
        return c;
    };
    if &head[..4] != b"RIFF" && &head[..4] != b"RIFX" {
        return Coverage::unrecognized();
    }
    let form = match &head[8..12] {
        b"WAVE" => "wav",
        b"WEBP" => "webp",
        b"AVI " => "avi",
        _ => "riff",
    };
    let mut cov = Coverage::new(form, 12);
    // The declared length covers everything after the 8-byte RIFF header.
    let declared = u64::from(u32::from_le_bytes([head[4], head[5], head[6], head[7]]));
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
    while at + 8 <= limit && seen < MAX_REGIONS {
        let id = &bytes[at..at + 4];
        let size = u32::from_le_bytes([bytes[at + 4], bytes[at + 5], bytes[at + 6], bytes[at + 7]])
            as usize;
        let body = at + 8;
        let Some(end) = body.checked_add(size) else {
            cov.problem("chunk size overflows");
            break;
        };
        if end > limit {
            cov.problem("chunk extends past declared end");
            break;
        }
        // `LIST`/`INFO` metadata and WebP's `XMP `/`EXIF` hold author text.
        if matches!(id, b"LIST" | b"INFO" | b"XMP " | b"EXIF" | b"ID3 ") {
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

/// IFF: `FORM` + u32 big-endian length + form type, then `id`/`size` chunks.
/// Used by `.aiff` and `.aifc`.
pub(crate) fn iff(bytes: &[u8]) -> Coverage {
    let Some(head) = bytes.get(..12) else {
        let mut c = Coverage::unrecognized();
        c.problem("header truncated");
        return c;
    };
    if &head[..4] != b"FORM" {
        return Coverage::unrecognized();
    }
    let form = match &head[8..12] {
        b"AIFF" => "aiff",
        b"AIFC" => "aifc",
        _ => "iff",
    };
    let mut cov = Coverage::new(form, 12);
    let declared = u64::from(u32::from_be_bytes([head[4], head[5], head[6], head[7]]));
    cov.declared_len = Some(declared.saturating_add(8));
    if declared.saturating_add(8) > bytes.len() as u64 {
        cov.problem("declared size exceeds file");
    }

    let limit = usize::try_from(declared.saturating_add(8))
        .unwrap_or(usize::MAX)
        .min(bytes.len());
    let mut at = 12usize;
    let mut seen = 0usize;
    while at + 8 <= limit && seen < MAX_REGIONS {
        let id = &bytes[at..at + 4];
        let size = u32::from_be_bytes([bytes[at + 4], bytes[at + 5], bytes[at + 6], bytes[at + 7]])
            as usize;
        let body = at + 8;
        let Some(end) = body.checked_add(size) else {
            cov.problem("chunk size overflows");
            break;
        };
        if end > limit {
            cov.problem("chunk extends past declared end");
            break;
        }
        // `NAME`/`AUTH`/`ANNO`/`(c) ` are AIFF's free-text chunks.
        if matches!(id, b"NAME" | b"AUTH" | b"ANNO" | b"(c) ") {
            cov.claim_freeform(at as u64, end as u64);
        } else {
            cov.claim(at as u64, end as u64);
        }
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
    let Some(head) = bytes.get(..6) else {
        return Coverage::unrecognized();
    };
    // reserved must be 0; type is 1 (icon) or 2 (cursor).
    let kind = u16::from_le_bytes([head[2], head[3]]);
    if head[0] != 0 || head[1] != 0 || !matches!(kind, 1 | 2) {
        return Coverage::unrecognized();
    }
    let count = u16::from_le_bytes([head[4], head[5]]) as usize;
    if count == 0 || count > 512 {
        return Coverage::unrecognized();
    }
    let dir_end = 6 + count * 16;
    if dir_end > bytes.len() {
        let mut c = Coverage::new(if kind == 1 { "ico" } else { "cur" }, 6);
        c.problem("icon directory truncated");
        return c;
    }
    let mut cov = Coverage::new(if kind == 1 { "ico" } else { "cur" }, dir_end as u64);
    for i in 0..count {
        let e = &bytes[6 + i * 16..6 + (i + 1) * 16];
        let size = u32::from_le_bytes([e[8], e[9], e[10], e[11]]) as u64;
        let off = u32::from_le_bytes([e[12], e[13], e[14], e[15]]) as u64;
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
    if bytes.len() < 13 || (!bytes.starts_with(b"GIF87a") && !bytes.starts_with(b"GIF89a")) {
        return Coverage::unrecognized();
    }
    let mut at = 13usize;
    let flags = bytes[10];
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
    while at < bytes.len() && seen < MAX_REGIONS {
        match bytes[at] {
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
                let Some(desc) = bytes.get(at..at + 10) else {
                    cov.problem("image descriptor truncated");
                    break;
                };
                let local = desc[9];
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
    let Some(head) = bytes.get(..14) else {
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
    let framed = bytes.len() >= 2 && bytes[0] == 0xFF && (bytes[1] & 0xE0) == 0xE0;
    if !has_id3 && !framed {
        return Coverage::unrecognized();
    }
    let mut start = 0u64;
    let mut cov = Coverage::new("mp3", 0);
    if has_id3 {
        let Some(head) = bytes.get(..10) else {
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
    if bytes.len() >= 128 && bytes[bytes.len() - 128..].starts_with(b"TAG") {
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
    let Some(head) = bytes.get(..8) else {
        return Coverage::unrecognized();
    };
    if &head[4..8] != b"ftyp" {
        return Coverage::unrecognized();
    }
    let mut cov = Coverage::new("iso-bmff", 0);
    let mut at = 0usize;
    let mut seen = 0usize;
    while at + 8 <= bytes.len() && seen < MAX_REGIONS {
        let size32 =
            u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]) as u64;
        let btype = &bytes[at + 4..at + 8];
        let size = match size32 {
            // 0 means "extends to end of file".
            0 => bytes.len() as u64 - at as u64,
            // 1 means a 64-bit size follows the type.
            1 => {
                let Some(ext) = bytes.get(at + 8..at + 16) else {
                    cov.problem("64-bit box size truncated");
                    break;
                };
                u64::from_be_bytes([
                    ext[0], ext[1], ext[2], ext[3], ext[4], ext[5], ext[6], ext[7],
                ])
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
        if matches!(btype, b"udta" | b"meta" | b"free" | b"skip") {
            cov.claim_freeform(at as u64, end);
        } else {
            cov.claim(at as u64, end);
        }
        at = end as usize;
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
    // Case-insensitive search for the final closing tag.
    let lower: Vec<u8> = bytes.iter().map(|b| b.to_ascii_lowercase()).collect();
    match memchr::memmem::rfind(&lower, b"</svg>") {
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
mod tests {
    use super::*;
    use crate::formats::carrier;
    use crate::output::{Metrics, Values};

    fn facts(cov: &Coverage, bytes: &[u8]) -> (Values, Metrics) {
        let mut v = Values::new();
        let mut m = Metrics::new();
        carrier::emit(bytes, cov, &mut v, &mut m);
        (v, m)
    }

    fn stow(v: &Values) -> Vec<String> {
        v.get("media.stowaway")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn fake_pe(body: usize) -> Vec<u8> {
        let mut out = vec![0u8; 0x40];
        out[0] = b'M';
        out[1] = b'Z';
        out[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        out.extend_from_slice(b"PE\0\0");
        // Non-printable filler: repeated 'A' would classify as text/base64
        // and mask which layer a failure came from.
        out.extend((0..body).map(|i| (i % 251) as u8));
        out
    }

    fn build_wav(extra: &[u8]) -> Vec<u8> {
        let fmt = [1u8, 0, 1, 0, 0x40, 0x1f, 0, 0, 0x40, 0x1f, 0, 0, 1, 0, 8, 0];
        let data = vec![0x80u8; 512];
        let mut body = Vec::from(*b"WAVE");
        body.extend_from_slice(b"fmt ");
        body.extend_from_slice(&(fmt.len() as u32).to_le_bytes());
        body.extend_from_slice(&fmt);
        body.extend_from_slice(b"data");
        body.extend_from_slice(&(data.len() as u32).to_le_bytes());
        body.extend_from_slice(&data);
        let mut out = Vec::from(*b"RIFF");
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&body);
        out.extend_from_slice(extra);
        out
    }

    #[test]
    fn clean_wav_is_valid() {
        let wav = build_wav(&[]);
        let (v, m) = facts(&riff(&wav), &wav);
        assert_eq!(
            v.get("media.container").and_then(|x| x.as_str()),
            Some("wav")
        );
        assert_eq!(v.get("media.valid").and_then(|x| x.as_bool()), Some(true));
        assert_eq!(m.get("media.trailing_bytes"), Some(0.0));
        assert!(stow(&v).is_empty());
    }

    #[test]
    fn wav_with_appended_executable_is_caught() {
        let wav = build_wav(&fake_pe(4096));
        let (v, m) = facts(&riff(&wav), &wav);
        assert_eq!(stow(&v), vec!["pe"]);
        assert!(m.get("media.trailing_bytes").unwrap() > 4000.0);
        assert_eq!(v.get("media.valid").and_then(|x| x.as_bool()), Some(false));
    }

    fn build_ico(extra: &[u8]) -> Vec<u8> {
        let img = vec![0x11u8; 256];
        let mut out = Vec::new();
        out.extend_from_slice(&[0, 0, 1, 0, 1, 0]);
        out.extend_from_slice(&[16, 16, 0, 0, 1, 0, 32, 0]);
        out.extend_from_slice(&(img.len() as u32).to_le_bytes());
        out.extend_from_slice(&22u32.to_le_bytes());
        out.extend_from_slice(&img);
        out.extend_from_slice(extra);
        out
    }

    #[test]
    fn clean_icon_is_valid_and_payload_is_caught() {
        let clean = build_ico(&[]);
        let (v, _) = facts(&ico(&clean), &clean);
        assert_eq!(
            v.get("media.container").and_then(|x| x.as_str()),
            Some("ico")
        );
        assert_eq!(v.get("media.valid").and_then(|x| x.as_bool()), Some(true));

        let armed = build_ico(&fake_pe(2048));
        let (v, m) = facts(&ico(&armed), &armed);
        assert_eq!(stow(&v), vec!["pe"]);
        assert!(m.get("media.trailing_bytes").unwrap() > 2000.0);
    }

    fn build_gif(extra: &[u8]) -> Vec<u8> {
        let mut out = Vec::from(*b"GIF89a");
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.push(0x80); // global colour table, 2 entries
        out.push(0);
        out.push(0);
        out.extend_from_slice(&[0, 0, 0, 0xff, 0xff, 0xff]);
        out.push(0x2C);
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.push(0);
        out.push(2); // LZW min code size
        out.extend_from_slice(&[2, 0x44, 0x01, 0]);
        out.push(0x3B);
        out.extend_from_slice(extra);
        out
    }

    #[test]
    fn clean_gif_is_valid_and_trailing_payload_is_caught() {
        let clean = build_gif(&[]);
        let (v, _) = facts(&gif(&clean), &clean);
        assert_eq!(
            v.get("media.container").and_then(|x| x.as_str()),
            Some("gif")
        );
        assert_eq!(v.get("media.valid").and_then(|x| x.as_bool()), Some(true));

        let armed = build_gif(&fake_pe(1024));
        let (v, _) = facts(&gif(&armed), &armed);
        assert_eq!(stow(&v), vec!["pe"]);
    }

    fn build_aiff(extra: &[u8]) -> Vec<u8> {
        let comm = [
            0u8, 1, 0, 0, 2, 0, 0, 8, 0x40, 0x0b, 0xfa, 0, 0, 0, 0, 0, 0, 0,
        ];
        let ssnd = vec![0u8; 520];
        let mut body = Vec::from(*b"AIFF");
        body.extend_from_slice(b"COMM");
        body.extend_from_slice(&(comm.len() as u32).to_be_bytes());
        body.extend_from_slice(&comm);
        body.extend_from_slice(b"SSND");
        body.extend_from_slice(&(ssnd.len() as u32).to_be_bytes());
        body.extend_from_slice(&ssnd);
        let mut out = Vec::from(*b"FORM");
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out.extend_from_slice(extra);
        out
    }

    #[test]
    fn clean_aiff_is_valid_and_payload_is_caught() {
        let clean = build_aiff(&[]);
        let (v, _) = facts(&iff(&clean), &clean);
        assert_eq!(
            v.get("media.container").and_then(|x| x.as_str()),
            Some("aiff")
        );
        assert_eq!(v.get("media.valid").and_then(|x| x.as_bool()), Some(true));

        // Above `CONCEALMENT_FLOOR`: a few dozen stray bytes are format drift,
        // not a payload, and the floor exists so they are not reported as one.
        let mut payload = Vec::from(*b"PK\x03\x04");
        payload.extend((0..512).map(|i| (i % 251) as u8));
        let armed = build_aiff(&payload);
        let (v, _) = facts(&iff(&armed), &armed);
        assert!(stow(&v).contains(&"zip".to_string()));
    }

    #[test]
    fn bmp_declared_size_bounds_the_file() {
        let mut out = Vec::from(*b"BM");
        out.extend_from_slice(&512u32.to_le_bytes());
        out.extend_from_slice(&[0; 8]);
        out.resize(512, 0x20);
        let (v, _) = facts(&bmp(&out), &out);
        assert_eq!(v.get("media.valid").and_then(|x| x.as_bool()), Some(true));

        out.extend_from_slice(&fake_pe(1024));
        let (v, _) = facts(&bmp(&out), &out);
        assert_eq!(stow(&v), vec!["pe"]);
    }

    #[test]
    fn mp3_id3_is_freeform_and_appended_payload_is_caught() {
        let mut out = Vec::from(*b"ID3");
        out.extend_from_slice(&[3, 0, 0]);
        out.extend_from_slice(&[0, 0, 0x01, 0x00]); // syncsafe 128
        out.extend_from_slice(&[0x41; 128]);
        out.extend_from_slice(&[0xFF, 0xFB]);
        out.extend_from_slice(&[0u8; 400]);
        let (v, m) = facts(&mp3(&out), &out);
        assert_eq!(
            v.get("media.container").and_then(|x| x.as_str()),
            Some("mp3")
        );
        // The 128-byte ASCII ID3 body is author content, not concealed space.
        assert_eq!(m.get("media.stowaway_bytes"), Some(0.0));
        assert!(stow(&v).is_empty());
    }

    #[test]
    fn iso_bmff_walks_boxes_and_flags_appended_data() {
        let mut out = Vec::new();
        out.extend_from_slice(&16u32.to_be_bytes());
        out.extend_from_slice(b"ftyp");
        out.extend_from_slice(b"isom\0\0\x02\0");
        out.extend_from_slice(&520u32.to_be_bytes());
        out.extend_from_slice(b"mdat");
        out.extend_from_slice(&[0u8; 512]);
        let (v, _) = facts(&iso_bmff(&out), &out);
        assert_eq!(
            v.get("media.container").and_then(|x| x.as_str()),
            Some("iso-bmff")
        );
        assert_eq!(v.get("media.valid").and_then(|x| x.as_bool()), Some(true));

        out.extend_from_slice(&fake_pe(2048));
        let (v, _) = facts(&iso_bmff(&out), &out);
        assert_eq!(stow(&v), vec!["pe"]);
    }

    #[test]
    fn non_container_bytes_are_unrecognized() {
        for probe in [
            &b"not a container at all"[..],
            &b"MZ\x90\x00\x03\x00\x00\x00"[..],
        ] {
            assert!(riff(probe).container.is_none());
            assert!(iff(probe).container.is_none());
            assert!(gif(probe).container.is_none());
            assert!(iso_bmff(probe).container.is_none());
        }
    }

    #[test]
    fn truncated_inputs_do_not_panic() {
        for n in 0..24usize {
            let short = vec![0x41u8; n];
            let _ = riff(&short);
            let _ = iff(&short);
            let _ = ico(&short);
            let _ = gif(&short);
            let _ = bmp(&short);
            let _ = mp3(&short);
            let _ = iso_bmff(&short);
        }
    }

    #[test]
    fn svg_document_ends_at_closing_tag() {
        let doc = b"<svg xmlns=\"http://www.w3.org/2000/svg\"><rect/></svg>\n";
        let (v, m) = facts(&svg(doc), doc);
        assert_eq!(v.get("media.valid").and_then(|x| x.as_bool()), Some(true));
        assert_eq!(m.get("media.trailing_bytes"), Some(0.0));

        let mut armed = doc.to_vec();
        armed.extend_from_slice(&fake_pe(2048));
        let (v, m) = facts(&svg(&armed), &armed);
        assert_eq!(stow(&v), vec!["pe"]);
        assert!(m.get("media.trailing_bytes").unwrap() > 2000.0);
    }

    /// A fragment with no closing tag has no establishable boundary, so
    /// nothing may be reported as hidden past it.
    #[test]
    fn svg_fragment_reports_no_trailing_data() {
        let frag = b"<svg xmlns=\"http://www.w3.org/2000/svg\"><rect/>";
        let (_, m) = facts(&svg(frag), frag);
        assert_eq!(m.get("media.trailing_bytes"), Some(0.0));
    }
}
