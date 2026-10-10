//! JPEG extractor.
//!
//! Walks the JPEG marker segment stream surfacing EXIF attribution
//! (Make / Model / Software / DateTime), ICC/IPTC/XMP/Photoshop IRB
//! presence flags, and stego-relevant counts (concatenated SOIs,
//! comment density, MakerNote bytes). No pixel decode.
//!
//! Schema (no `has_*` bools per the filefacts convention — presence
//! is signaled via the `jpeg.features[]` array):
//!
//! - `jpeg.exif.{make, model, software, datetime, datetime_original,
//!   artist, copyright}` — IFD0/ExifIFD tag values.
//! - `jpeg.comment` — COM segment text.
//! - `jpeg.adobe_color_transform` — APP14 Adobe color-transform byte.
//! - `jpeg.features[]` — Pike-style flag array: `exif`, `gps`, `icc`,
//!   `iptc`, `photoshop_irb`, `xmp`, `jfif_thumbnail`,
//!   `concatenated_jpegs`.
//! - `jpeg.{segment_count, app_segment_count, com_count, dqt_count,
//!   dht_count, soi_count, maker_note_bytes}` — flat metrics.

use crate::formats::carrier::{self, Coverage};
use crate::metric;
use crate::value_key;
use serde_json::{Value as JsonValue, json};

use crate::formats::common::{XorScan, extract_binary_strings, put_str};
use crate::formats::image_stats;
use crate::output::{Metrics, Strings, Values};
use crate::scan::entropy;

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
) {
    extract_binary_strings(bytes, strings, XorScan::No);

    let mut coverage = Coverage::new("jpeg", 2);
    if !bytes.starts_with(&[0xFF, 0xD8]) {
        carrier::emit(bytes, &Coverage::unrecognized(), values, metrics);
        return;
    }

    let mut state = JpegState::default();
    state.soi_count = 1;
    let mut pos = 2usize;
    let mut eoi_pos: Option<usize> = None;

    // The two bytes at `pos`, when both are present: a segment length, or
    // the pair the entropy-coded scan is searched through.
    let pair = |pos: usize| bytes.get(pos..).and_then(<[u8]>::first_chunk::<2>);

    loop {
        while bytes.get(pos).is_some_and(|&b| b != 0xFF) {
            pos += 1;
        }
        while bytes.get(pos) == Some(&0xFF) {
            pos += 1;
        }
        let Some(&marker) = bytes.get(pos) else {
            break;
        };
        // The segment starts at its 0xFF prefix, one byte before the marker.
        let seg_start = pos.saturating_sub(1);
        pos += 1;
        state.segment_count += 1;

        match marker {
            0xD8 => state.soi_count += 1,
            0xD9 => {
                eoi_pos = Some(pos);
                break;
            }
            0xD0..=0xD7 | 0x01 => continue,
            0xDA => {
                state.scan_count = state.scan_count.saturating_add(1);
                let Some(&len) = pair(pos) else {
                    break;
                };
                pos += usize::from(u16::from_be_bytes(len));
                while let Some(&[b0, b1]) = pair(pos) {
                    if b0 == 0xFF && b1 != 0x00 && b1 != 0xFF {
                        break;
                    }
                    pos += 1;
                }
            }
            _ => {
                let Some(&len) = pair(pos) else {
                    break;
                };
                let seg_len = usize::from(u16::from_be_bytes(len));
                if seg_len < 2 {
                    break;
                }
                let body_start = pos + 2;
                let body_end = pos + seg_len;
                let Some(body) = bytes.get(body_start..body_end) else {
                    break;
                };

                let payload_len = seg_len - 2;
                match marker {
                    0xFE => {
                        state.com_count += 1;
                        state.comment_bytes =
                            state.comment_bytes.saturating_add(payload_len as u64);
                    }
                    0xE1 => {
                        state.exif_size = state.exif_size.saturating_add(payload_len as u64);
                    }
                    0xDB => state.dqt_count += 1,
                    0xC4 => state.dht_count += 1,
                    _ => {}
                }
                if (0xE0..=0xEF).contains(&marker) {
                    state.app_segment_count += 1;
                }

                handle_segment(marker, body, &mut state);
                // Only the metadata segments are recorded, as windows into
                // the image span claimed below. Claiming every segment
                // individually left the entropy-coded data between restart
                // markers unclaimed, which read as concealed space on 25 of
                // the 897 real media files this was measured against.
                if marker == 0xFE || (0xE0..=0xEF).contains(&marker) {
                    coverage.claim_freeform(seg_start as u64, body_end as u64);
                }
                pos = body_end;
            }
        }
    }

    // The image is everything from SOI to EOI. A decoder stops at EOI, so
    // that — not the last segment header — is where the file logically ends.
    if let Some(eoi) = eoi_pos {
        coverage.claim(2, eoi as u64);
    } else {
        // The segment walk never reached an end-of-image marker, so where the
        // image stops is unknown. Claim to EOF rather than reporting the
        // remainder as concealed: a boundary we could not establish is not
        // evidence of one being hidden, and treating it as such flagged 23 of
        // the 897 real media files this was measured against.
        coverage.claim(2, bytes.len() as u64);
    }
    carrier::emit(bytes, &coverage, values, metrics);

    if state.soi_count > 1 {
        state.features.push("concatenated_jpegs");
    }

    // Emit kv.
    if state.exif_present {
        let mut exif = serde_json::Map::new();
        if let Some(v) = state.exif_make {
            exif.insert("make".into(), JsonValue::String(v));
        }
        if let Some(v) = state.exif_model {
            exif.insert("model".into(), JsonValue::String(v));
        }
        if let Some(v) = state.exif_software {
            exif.insert("software".into(), JsonValue::String(v));
        }
        if let Some(v) = state.exif_datetime {
            exif.insert("datetime".into(), JsonValue::String(v));
        }
        if let Some(v) = state.exif_datetime_original {
            exif.insert("datetime_original".into(), JsonValue::String(v));
        }
        if let Some(v) = state.exif_artist {
            exif.insert("artist".into(), JsonValue::String(v));
        }
        if let Some(v) = state.exif_copyright {
            exif.insert("copyright".into(), JsonValue::String(v));
        }
        if !exif.is_empty() {
            values.insert_key(value_key!("jpeg.exif"), JsonValue::Object(exif));
        }
        state.features.insert(0, "exif");
    }
    if let Some(c) = state.comment {
        put_str(values, value_key!("jpeg.comment"), c);
    }
    if let Some(t) = state.adobe_color_transform {
        // Nest under `jpeg.adobe.*` so additional APP14 fields
        // (DCTEncodeVersion, APP14Flags0/1) can land here in the
        // future without renaming the existing key.
        values.insert_key(value_key!("jpeg.adobe.color_transform"), json!(t));
    }
    if !state.features.is_empty() {
        values.insert_key(
            value_key!("jpeg.features"),
            JsonValue::Array(
                state
                    .features
                    .into_iter()
                    .map(|s| JsonValue::String(s.into()))
                    .collect(),
            ),
        );
    }

    metrics.insert(
        metric!("jpeg.segment_count"),
        f64::from(state.segment_count),
    );
    metrics.insert(
        metric!("jpeg.app_segment_count"),
        f64::from(state.app_segment_count),
    );
    metrics.insert(metric!("jpeg.com_count"), f64::from(state.com_count));
    metrics.insert(metric!("jpeg.dqt_count"), f64::from(state.dqt_count));
    metrics.insert(metric!("jpeg.dht_count"), f64::from(state.dht_count));
    metrics.insert(metric!("jpeg.soi_count"), f64::from(state.soi_count));
    metrics.insert(
        metric!("jpeg.maker_note_bytes"),
        f64::from(state.maker_note_bytes),
    );
    metrics.insert(metric!("jpeg.comment_bytes"), state.comment_bytes as f64);
    metrics.insert(metric!("jpeg.exif_size"), state.exif_size as f64);
    let appended_bytes = eoi_pos.map_or(0u64, |p| bytes.len().saturating_sub(p) as u64);
    metrics.insert(metric!("jpeg.trailing_bytes"), appended_bytes as f64);

    // Best-effort pixel-statistic pass. Decoder errors are swallowed —
    // a JPEG with a weird color space or a truncated bitstream still
    // gets the structural metrics above.
    extract_pixel_stats(bytes, state.scan_count, metrics);
}

/// Scans past which the pixel pass is skipped. The decoder walks every
/// block of the image once per scan, and a progressive scan can cover all of
/// them with a few bytes of end-of-band runs, so a small file of thousands of
/// scans over a large image took minutes. Encoders write about a dozen.
const MAX_DECODE_SCANS: u32 = 100;

/// Decode the JPEG (cap-protected) and emit pixel-statistic metrics:
/// dimensions, per-channel entropy, edge density, histogram flatness.
/// Whole-file `file.entropy` is not repeated here: the generic pass emits it
/// for every file before this extractor runs. `scans` is the segment walk's
/// count of start-of-scan markers; past [`MAX_DECODE_SCANS`] only the header
/// facts are emitted.
fn extract_pixel_stats(bytes: &[u8], scans: u32, metrics: &mut Metrics) {
    use jpeg_decoder::Decoder;
    use std::io::Cursor;

    let mut decoder = Decoder::new(Cursor::new(bytes));
    if decoder.read_info().is_err() {
        return;
    }
    let Some(info) = decoder.info() else {
        return;
    };
    let width = u32::from(info.width);
    let height = u32::from(info.height);
    let channels: u32 = match info.pixel_format {
        jpeg_decoder::PixelFormat::L8 | jpeg_decoder::PixelFormat::L16 => 1,
        jpeg_decoder::PixelFormat::RGB24 => 3,
        jpeg_decoder::PixelFormat::CMYK32 => 4,
    };

    metrics.insert(metric!("image.width"), f64::from(width));
    metrics.insert(metric!("image.height"), f64::from(height));
    metrics.insert(metric!("image.channels"), f64::from(channels));

    let predicted = (width as usize)
        .saturating_mul(height as usize)
        .saturating_mul(channels as usize);
    if predicted > image_stats::MAX_DECODE_BYTES || scans > MAX_DECODE_SCANS {
        return;
    }
    let Ok(pixels) = decoder.decode() else {
        return;
    };

    let pixel_entropy = entropy::shannon(&pixels);
    metrics.insert(metric!("image.pixel_entropy"), pixel_entropy);
    metrics.insert(metric!("image.histogram_flatness"), pixel_entropy / 8.0);
    let density =
        image_stats::edge_density(&pixels, width as usize, height as usize, channels as usize);
    metrics.insert(metric!("image.edge_density"), f64::from(density));

    let (r, g, b, _a) = if channels >= 3 {
        image_stats::channel_entropy(&pixels, channels as usize)
    } else {
        (0.0, 0.0, 0.0, 0.0)
    };
    metrics.insert(metric!("image.r_entropy"), f64::from(r));
    metrics.insert(metric!("image.g_entropy"), f64::from(g));
    metrics.insert(metric!("image.b_entropy"), f64::from(b));
}

#[derive(Default)]
struct JpegState {
    segment_count: u32,
    /// Start-of-scan markers seen by the segment walk.
    scan_count: u32,
    app_segment_count: u32,
    com_count: u32,
    dqt_count: u32,
    dht_count: u32,
    soi_count: u32,
    maker_note_bytes: u32,
    comment_bytes: u64,
    exif_size: u64,
    exif_present: bool,
    exif_make: Option<String>,
    exif_model: Option<String>,
    exif_software: Option<String>,
    exif_datetime: Option<String>,
    exif_datetime_original: Option<String>,
    exif_artist: Option<String>,
    exif_copyright: Option<String>,
    comment: Option<String>,
    adobe_color_transform: Option<u8>,
    features: Vec<&'static str>,
}

fn handle_segment(marker: u8, body: &[u8], st: &mut JpegState) {
    match marker {
        0xFE => {
            if let Ok(s) = std::str::from_utf8(body) {
                let trimmed = s.trim_end_matches(|c: char| c == '\0' || c.is_whitespace());
                if !trimmed.is_empty() {
                    st.comment = Some(trimmed.to_string());
                }
            }
        }
        // Bytes 12 and 13 are the thumbnail width and height.
        0xE0 if body.starts_with(b"JFIF\0")
            && matches!(body.get(12..14), Some(&[w, h]) if w != 0 && h != 0) =>
        {
            if !st.features.contains(&"jfif_thumbnail") {
                st.features.push("jfif_thumbnail");
            }
        }
        0xE1 => {
            if let Some(tiff) = body.strip_prefix(b"Exif\0\0") {
                st.exif_present = true;
                parse_exif_app1(tiff, st);
            } else if body
                .windows(b"http://ns.adobe.com/xap/1.0/".len())
                .any(|w| w == b"http://ns.adobe.com/xap/1.0/")
            {
                if !st.features.contains(&"xmp") {
                    st.features.push("xmp");
                }
            }
        }
        0xE2 if body.starts_with(b"ICC_PROFILE\0") && body.len() >= 14 + 84 => {
            if !st.features.contains(&"icc") {
                st.features.push("icc");
            }
        }
        0xED if body.starts_with(b"Photoshop 3.0\0") => {
            if !st.features.contains(&"photoshop_irb") {
                st.features.push("photoshop_irb");
            }
            if body.get(14..18) == Some(b"8BIM") && !st.features.contains(&"iptc") {
                st.features.push("iptc");
            }
        }
        // A short APP14 records nothing, exactly as the catch-all arm would.
        0xEE if body.starts_with(b"Adobe\0") => {
            if let Some(&transform) = body.get(11) {
                st.adobe_color_transform = Some(transform);
            }
        }
        _ => {}
    }
}

/// Walk a TIFF-encapsulated EXIF block (after the leading
/// `"Exif\0\0"` header). Reads IFD0 and one level of ExifIFD /
/// GPS-IFD sub-pointers — that covers Make/Model/Software/
/// DateTime/Artist/Copyright/DateTimeOriginal/MakerNote.
fn parse_exif_app1(tiff: &[u8], st: &mut JpegState) {
    let Some(&[o0, o1, m0, m1, i0, i1, i2, i3]) = tiff.first_chunk::<8>() else {
        return;
    };
    let little = match [o0, o1] {
        [b'I', b'I'] => true,
        [b'M', b'M'] => false,
        _ => return,
    };
    let magic = if little {
        u16::from_le_bytes([m0, m1])
    } else {
        u16::from_be_bytes([m0, m1])
    };
    if magic != 0x002A {
        return;
    }
    let ifd0_off = if little {
        u32::from_le_bytes([i0, i1, i2, i3])
    } else {
        u32::from_be_bytes([i0, i1, i2, i3])
    } as usize;
    walk_ifd(tiff, ifd0_off, little, st, true);
}

fn walk_ifd(tiff: &[u8], off: usize, little: bool, st: &mut JpegState, is_root: bool) {
    let read_u16 = |o: usize| -> Option<u16> {
        let b = *tiff.get(o..)?.first_chunk()?;
        Some(if little {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        })
    };
    let read_u32 = |o: usize| -> Option<u32> {
        let b = *tiff.get(o..)?.first_chunk()?;
        Some(if little {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    };
    let count = match read_u16(off) {
        Some(c) => c as usize,
        None => return,
    };
    let mut exif_ifd_off: Option<usize> = None;
    let mut gps_present = false;
    for i in 0..count {
        // `off` is file-controlled; an entry past the address space is past
        // the end of the block, like any other unreadable entry.
        let Some(entry_off) = off.checked_add(2 + i * 12) else {
            return;
        };
        let Some(tag) = read_u16(entry_off) else {
            return;
        };
        let Some(typ) = read_u16(entry_off + 2) else {
            return;
        };
        let Some(cnt) = read_u32(entry_off + 4) else {
            return;
        };
        let value_off_field = entry_off + 8;

        let component_size = match typ {
            1 | 2 | 6 | 7 => 1,
            3 | 8 => 2,
            4 | 9 | 11 => 4,
            5 | 10 | 12 => 8,
            _ => 0,
        };
        let total_bytes = (cnt as usize).saturating_mul(component_size);
        let data_slice: Option<&[u8]> = if total_bytes <= 4 {
            tiff.get(value_off_field..value_off_field + total_bytes.min(4))
        } else if let Some(abs) = read_u32(value_off_field).map(|v| v as usize) {
            abs.checked_add(total_bytes)
                .and_then(|end| tiff.get(abs..end))
        } else {
            None
        };

        match tag {
            0x010F => st.exif_make = ascii_value(data_slice),
            0x0110 => st.exif_model = ascii_value(data_slice),
            0x0131 => st.exif_software = ascii_value(data_slice),
            0x0132 => st.exif_datetime = ascii_value(data_slice),
            0x013B => st.exif_artist = ascii_value(data_slice),
            0x8298 => st.exif_copyright = ascii_value(data_slice),
            0x9003 if !is_root => st.exif_datetime_original = ascii_value(data_slice),
            0x927C if !is_root => {
                st.maker_note_bytes = st
                    .maker_note_bytes
                    .saturating_add(crate::bytes::sat_u32(total_bytes));
            }
            0x8769 if is_root => {
                exif_ifd_off = Some(read_u32(value_off_field).unwrap_or(0) as usize)
            }
            0x8825 if is_root => gps_present = true,
            _ => {}
        }
    }
    if is_root {
        if let Some(off) = exif_ifd_off {
            walk_ifd(tiff, off, little, st, false);
        }
        if gps_present && !st.features.contains(&"gps") {
            st.features.push("gps");
        }
    }
}

fn ascii_value(bytes: Option<&[u8]>) -> Option<String> {
    let s = std::str::from_utf8(bytes?).ok()?;
    let trimmed = s.trim_end_matches(|c: char| c == '\0' || c.is_whitespace());
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_jpeg(segments: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut out = vec![0xFF, 0xD8];
        for (marker, body) in segments {
            out.push(0xFF);
            out.push(*marker);
            let len = (body.len() + 2) as u16;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(body);
        }
        out.extend_from_slice(&[0xFF, 0xD9]);
        out
    }

    fn run(bytes: &[u8]) -> (Values, Metrics) {
        let mut v = Values::new();
        let mut s = Strings::default();
        let mut m = Metrics::new();
        extract(bytes, &mut v, &mut s, &mut m);
        (v, m)
    }

    /// A progressive JPEG of a 4096x4096 image whose AC scans each cover
    /// every block with two 32767-block end-of-band runs: 25 bytes per scan
    /// that the decoder walks 262,144 blocks for.
    fn eob_run_scans(scans: usize) -> Vec<u8> {
        let mut out = vec![0xFF, 0xD8];
        let mut segment = |marker: u8, body: &[u8]| {
            out.extend_from_slice(&[0xFF, marker]);
            out.extend_from_slice(&((body.len() + 2) as u16).to_be_bytes());
            out.extend_from_slice(body);
        };
        let mut dqt = vec![0x00];
        dqt.extend([1u8; 64]);
        segment(0xDB, &dqt);
        segment(0xC2, &[8, 0x10, 0x00, 0x10, 0x00, 1, 1, 0x11, 0]);
        // One-symbol Huffman tables: DC category 0, AC EOBRUN of 2^14 + 14 bits.
        let mut dc = vec![0x00, 1];
        dc.extend([0u8; 15]);
        dc.push(0x00);
        segment(0xC4, &dc);
        let mut ac = vec![0x10, 1];
        ac.extend([0u8; 15]);
        ac.push(0xE0);
        segment(0xC4, &ac);
        segment(0xDA, &[1, 1, 0x00, 0, 0, 0x00]);
        out.extend(std::iter::repeat_n(0x00, 262_144 / 8));
        for _ in 0..scans {
            out.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 1, 1, 0x00, 1, 63, 0x00]);
            // `0` then fourteen `1`s is a run of 32767 blocks; eight cover
            // the image. Stuff each 0xFF with a zero byte.
            let bits = "011111111111111".repeat(8);
            let mut bits = bits.into_bytes();
            bits.resize(bits.len().div_ceil(8) * 8, b'1');
            for byte in bits.chunks(8) {
                let b = byte
                    .iter()
                    .fold(0u8, |acc, &c| (acc << 1) | u8::from(c == b'1'));
                out.push(b);
                if b == 0xFF {
                    out.push(0x00);
                }
            }
        }
        out.extend_from_slice(&[0xFF, 0xD9]);
        out
    }

    /// Thousands of cheap scans over a large image made the pixel decode
    /// walk billions of blocks. Past the scan cap only header facts remain.
    #[test]
    fn many_scans_skip_the_pixel_decode() {
        let started = std::time::Instant::now();
        let (_, m) = run(&eob_run_scans(5_000));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(m.get("image.width"), Some(4096.0));
        assert!(m.get("image.pixel_entropy").is_none());
        let (_, m) = run(&eob_run_scans(3));
        assert!(m.get("image.pixel_entropy").is_some());
    }

    #[test]
    fn rejects_non_jpeg() {
        let (v, _) = run(b"not a jpeg");
        assert!(v.get("jpeg.exif").is_none());
    }

    #[test]
    fn surfaces_comment() {
        let jpeg = build_jpeg(&[(0xFE, b"hello world".to_vec())]);
        let (v, m) = run(&jpeg);
        assert_eq!(
            v.get("jpeg.comment").and_then(|x| x.as_str()),
            Some("hello world")
        );
        assert_eq!(m.get("jpeg.com_count"), Some(1.0));
    }

    #[test]
    fn detects_concatenated_jpegs() {
        let data = vec![0xFF, 0xD8, 0xFF, 0xD8, 0xFF, 0xD9];
        let (v, m) = run(&data);
        let feats = v.get("jpeg.features").and_then(|x| x.as_array()).unwrap();
        let names: Vec<&str> = feats.iter().filter_map(|x| x.as_str()).collect();
        assert!(names.contains(&"concatenated_jpegs"));
        assert_eq!(m.get("jpeg.soi_count"), Some(2.0));
    }

    #[test]
    fn parses_exif_make_model_software_le() {
        let mut tiff = Vec::new();
        tiff.extend_from_slice(b"II");
        tiff.extend_from_slice(&0x002Au16.to_le_bytes());
        tiff.extend_from_slice(&8u32.to_le_bytes());
        tiff.extend_from_slice(&3u16.to_le_bytes());
        let mut data_blob: Vec<u8> = Vec::new();
        let strings = [
            (0x010Fu16, "Canon\0"),
            (0x0110, "EOS R5\0"),
            (0x0131, "Adobe LR\0"),
        ];
        let strings_offset_base = 8 + 2 + 12 * strings.len() + 4;
        for (tag, value) in &strings {
            tiff.extend_from_slice(&tag.to_le_bytes());
            tiff.extend_from_slice(&2u16.to_le_bytes());
            tiff.extend_from_slice(&(value.len() as u32).to_le_bytes());
            let offset = (strings_offset_base + data_blob.len()) as u32;
            tiff.extend_from_slice(&offset.to_le_bytes());
            data_blob.extend_from_slice(value.as_bytes());
        }
        tiff.extend_from_slice(&0u32.to_le_bytes());
        tiff.extend(data_blob);

        let mut body = b"Exif\0\0".to_vec();
        body.extend_from_slice(&tiff);
        let jpeg = build_jpeg(&[(0xE1, body)]);

        let (v, _) = run(&jpeg);
        let exif = v.get("jpeg.exif").and_then(|x| x.as_object()).unwrap();
        assert_eq!(exif.get("make").and_then(|x| x.as_str()), Some("Canon"));
        assert_eq!(exif.get("model").and_then(|x| x.as_str()), Some("EOS R5"));
        assert_eq!(
            exif.get("software").and_then(|x| x.as_str()),
            Some("Adobe LR")
        );
        let feats = v.get("jpeg.features").and_then(|x| x.as_array()).unwrap();
        let names: Vec<&str> = feats.iter().filter_map(|x| x.as_str()).collect();
        assert!(names.contains(&"exif"));
    }

    #[test]
    fn detects_icc_profile() {
        // APP2 ICC_PROFILE marker: 12 bytes ICC_PROFILE\0 +
        // chunk seq/total bytes + the 84-byte profile header.
        // Total body must be ≥ 14 + 84 = 98 bytes.
        let mut body = b"ICC_PROFILE\0".to_vec();
        body.extend_from_slice(&[1, 1]); // chunk_seq, chunk_total
        body.extend_from_slice(&[0; 84]); // profile header
        let jpeg = build_jpeg(&[(0xE2, body)]);
        let (v, _) = run(&jpeg);
        let feats = v.get("jpeg.features").and_then(|x| x.as_array()).unwrap();
        let names: Vec<&str> = feats.iter().filter_map(|x| x.as_str()).collect();
        assert!(names.contains(&"icc"));
    }

    #[test]
    fn detects_xmp_packet() {
        let mut body = b"http://ns.adobe.com/xap/1.0/\0".to_vec();
        body.extend_from_slice(b"<?xpacket begin=...?>");
        let jpeg = build_jpeg(&[(0xE1, body)]);
        let (v, _) = run(&jpeg);
        let feats = v.get("jpeg.features").and_then(|x| x.as_array()).unwrap();
        let names: Vec<&str> = feats.iter().filter_map(|x| x.as_str()).collect();
        assert!(names.contains(&"xmp"));
    }

    #[test]
    fn truncated_segment_doesnt_crash() {
        // SOI + an APP1 marker claiming 10000-byte length we don't supply.
        let buf = [0xFF, 0xD8, 0xFF, 0xE1, 0x27, 0x10];
        let (_, _) = run(&buf);
        // No panic, no assertion needed.
    }

    #[test]
    fn comment_bytes_metric_tracks_payload_size() {
        let jpeg = build_jpeg(&[(0xFE, b"hello world".to_vec())]);
        let (_, m) = run(&jpeg);
        assert_eq!(m.get("jpeg.comment_bytes"), Some(11.0));
    }

    #[test]
    fn appended_bytes_metric_tracks_post_eoi_data() {
        let mut jpeg = build_jpeg(&[]);
        jpeg.extend_from_slice(b"hidden payload");
        let (_, m) = run(&jpeg);
        assert_eq!(m.get("jpeg.trailing_bytes"), Some(14.0));
    }

    #[test]
    fn exif_size_metric_tracks_app1_payload() {
        // APP1 segment with EXIF prefix — exif_size = payload length.
        let mut body = b"Exif\0\0".to_vec();
        body.extend_from_slice(&[0u8; 20]);
        let jpeg = build_jpeg(&[(0xE1, body)]);
        let (_, m) = run(&jpeg);
        // payload = "Exif\0\0" (6) + 20 zeros = 26.
        assert_eq!(m.get("jpeg.exif_size"), Some(26.0));
    }

    /// `file.entropy` comes from the generic pass that runs ahead of every
    /// extractor, so the JPEG extractor no longer computes it a second time;
    /// the full pipeline still reports it, decodable or not.
    #[test]
    fn file_entropy_comes_from_the_generic_pass() {
        let jpeg = build_jpeg(&[(0xFE, b"hello".to_vec())]);
        let (_, m) = run(&jpeg);
        assert!(m.get("file.entropy").is_none());

        // Bytes that pass the SOI check but aren't decodable.
        for bytes in [jpeg, vec![0xFF, 0xD8, 0xFF, 0xD9]] {
            let parsed = crate::OpenOptions::new()
                .path(std::path::Path::new("x.jpg"))
                .open(&bytes);
            assert_eq!(parsed.fileid().file_type(), crate::FileType::Jpeg);
            let h = parsed.metrics().get("file.entropy").unwrap();
            assert!((h - entropy::shannon(&bytes)).abs() < 1e-9);
        }
    }

    #[test]
    fn detects_photoshop_irb_with_iptc() {
        let mut body = b"Photoshop 3.0\0".to_vec();
        body.extend_from_slice(b"8BIM");
        body.extend_from_slice(&[0; 8]);
        let jpeg = build_jpeg(&[(0xED, body)]);
        let (v, _) = run(&jpeg);
        let feats = v.get("jpeg.features").and_then(|x| x.as_array()).unwrap();
        let names: Vec<&str> = feats.iter().filter_map(|x| x.as_str()).collect();
        assert!(names.contains(&"photoshop_irb"));
        assert!(names.contains(&"iptc"));
    }
}
