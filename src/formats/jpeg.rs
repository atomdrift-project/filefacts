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
                    if b0 == 0xFF {
                        match b1 {
                            // Stuffed bytes and restart markers remain inside
                            // the entropy-coded scan. Returning to segment
                            // parsing at a restart loses that context and can
                            // misread a later FF 00 as a segment header.
                            0x00 | 0xD0..=0xD7 => {
                                pos += 2;
                                continue;
                            }
                            0xFF => {}
                            _ => break,
                        }
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

    let skipped = |reason: &str| {
        tracing::debug!(target: "filefacts::jpeg", stage = "pixel-stats", reason, "pixel statistics skipped");
    };
    let mut decoder = Decoder::new(Cursor::new(bytes));
    if let Err(e) = decoder.read_info() {
        return skipped(&format!("header did not decode: {e}"));
    }
    let Some(info) = decoder.info() else {
        return skipped("no frame header");
    };
    let width = u32::from(info.width);
    let height = u32::from(info.height);
    let format = info.pixel_format;
    let channels: u32 = match format {
        jpeg_decoder::PixelFormat::L8 | jpeg_decoder::PixelFormat::L16 => 1,
        jpeg_decoder::PixelFormat::RGB24 => 3,
        jpeg_decoder::PixelFormat::CMYK32 => 4,
    };

    metrics.insert(metric!("image.width"), f64::from(width));
    metrics.insert(metric!("image.height"), f64::from(height));
    metrics.insert(metric!("image.channels"), f64::from(channels));

    let predicted = (width as usize)
        .saturating_mul(height as usize)
        .saturating_mul(format.pixel_bytes());
    if predicted > image_stats::MAX_DECODE_BYTES {
        return skipped("decoded image larger than the decode cap");
    }
    if scans > MAX_DECODE_SCANS {
        return skipped("more scans than the decode cap");
    }
    let pixels = match decoder.decode() {
        Ok(raw) => eight_bit_samples(raw, format),
        Err(e) => return skipped(&format!("image did not decode: {e}")),
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

/// The decoded samples as one byte each, the unit every statistic counts in.
/// A 16-bit sample (lossless and 12-bit images, in native byte order)
/// contributes its high byte.
fn eight_bit_samples(decoded: Vec<u8>, format: jpeg_decoder::PixelFormat) -> Vec<u8> {
    match format {
        jpeg_decoder::PixelFormat::L16 => decoded
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&pair| u16::from_ne_bytes(pair).to_be_bytes()[0])
            .collect(),
        _ => decoded,
    }
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
mod tests;
