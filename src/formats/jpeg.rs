//! JPEG extractor.
//!
//! Walks the JPEG marker segment stream surfacing EXIF attribution
//! (Make / Model / Software / DateTime), ICC/IPTC/XMP/Photoshop IRB
//! presence flags, and stego-relevant counts (concatenated SOIs,
//! comment density, MakerNote bytes). No pixel decode.
//!
//! Schema (no `has_*` bools per the expose convention — presence
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

use serde_json::{json, Value as JsonValue};

use crate::error::Error;
use crate::formats::common::{extract_ascii_strings, put_str};
use crate::output::{Metrics, Strings, Values};

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
) -> Result<(), Error> {
    extract_ascii_strings(bytes, strings);

    if bytes.len() < 2 || bytes[0] != 0xFF || bytes[1] != 0xD8 {
        return Ok(());
    }

    let mut state = JpegState::default();
    state.soi_count = 1;
    let mut pos = 2usize;

    loop {
        while pos < bytes.len() && bytes[pos] != 0xFF {
            pos += 1;
        }
        while pos < bytes.len() && bytes[pos] == 0xFF {
            pos += 1;
        }
        if pos >= bytes.len() {
            break;
        }
        let marker = bytes[pos];
        pos += 1;
        state.segment_count += 1;

        match marker {
            0xD8 => state.soi_count += 1,
            0xD9 => break,
            0xD0..=0xD7 | 0x01 => continue,
            0xDA => {
                if pos + 1 >= bytes.len() {
                    break;
                }
                let seg_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
                pos += seg_len;
                while pos + 1 < bytes.len() {
                    if bytes[pos] == 0xFF && bytes[pos + 1] != 0x00 && bytes[pos + 1] != 0xFF {
                        break;
                    }
                    pos += 1;
                }
            }
            _ => {
                if pos + 1 >= bytes.len() {
                    break;
                }
                let seg_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
                if seg_len < 2 {
                    break;
                }
                let body_start = pos + 2;
                let body_end = pos + seg_len;
                if body_end > bytes.len() {
                    break;
                }
                let body = &bytes[body_start..body_end];

                match marker {
                    0xFE => state.com_count += 1,
                    0xDB => state.dqt_count += 1,
                    0xC4 => state.dht_count += 1,
                    _ => {}
                }
                if (0xE0..=0xEF).contains(&marker) {
                    state.app_segment_count += 1;
                }

                handle_segment(marker, body, &mut state);
                pos = body_end;
            }
        }
    }

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
            values.insert("jpeg.exif", JsonValue::Object(exif));
        }
        state.features.insert(0, "exif");
    }
    if let Some(c) = state.comment {
        put_str(values, "jpeg.comment", c);
    }
    if let Some(t) = state.adobe_color_transform {
        // Nest under `jpeg.adobe.*` so additional APP14 fields
        // (DCTEncodeVersion, APP14Flags0/1) can land here in the
        // future without renaming the existing key.
        values.insert("jpeg.adobe.color_transform", json!(t));
    }
    if !state.features.is_empty() {
        values.insert(
            "jpeg.features",
            JsonValue::Array(
                state
                    .features
                    .into_iter()
                    .map(|s| JsonValue::String(s.into()))
                    .collect(),
            ),
        );
    }

    metrics.insert("jpeg.segment_count", f64::from(state.segment_count));
    metrics.insert("jpeg.app_segment_count", f64::from(state.app_segment_count));
    metrics.insert("jpeg.com_count", f64::from(state.com_count));
    metrics.insert("jpeg.dqt_count", f64::from(state.dqt_count));
    metrics.insert("jpeg.dht_count", f64::from(state.dht_count));
    metrics.insert("jpeg.soi_count", f64::from(state.soi_count));
    metrics.insert("jpeg.maker_note_bytes", f64::from(state.maker_note_bytes));

    Ok(())
}

#[derive(Default)]
struct JpegState {
    segment_count: u32,
    app_segment_count: u32,
    com_count: u32,
    dqt_count: u32,
    dht_count: u32,
    soi_count: u32,
    maker_note_bytes: u32,
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
        0xE0 if body.starts_with(b"JFIF\0")
            && body.len() >= 14
            && body[12] != 0
            && body[13] != 0 =>
        {
            if !st.features.contains(&"jfif_thumbnail") {
                st.features.push("jfif_thumbnail");
            }
        }
        0xE1 => {
            if body.starts_with(b"Exif\0\0") {
                st.exif_present = true;
                parse_exif_app1(&body[6..], st);
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
        0xEE if body.starts_with(b"Adobe\0") && body.len() >= 12 => {
            st.adobe_color_transform = Some(body[11]);
        }
        _ => {}
    }
}

/// Walk a TIFF-encapsulated EXIF block (after the leading
/// `"Exif\0\0"` header). Reads IFD0 and one level of ExifIFD /
/// GPS-IFD sub-pointers — that covers Make/Model/Software/
/// DateTime/Artist/Copyright/DateTimeOriginal/MakerNote.
fn parse_exif_app1(tiff: &[u8], st: &mut JpegState) {
    if tiff.len() < 8 {
        return;
    }
    let little = match &tiff[..2] {
        b"II" => true,
        b"MM" => false,
        _ => return,
    };
    let magic = if little {
        u16::from_le_bytes([tiff[2], tiff[3]])
    } else {
        u16::from_be_bytes([tiff[2], tiff[3]])
    };
    if magic != 0x002A {
        return;
    }
    let ifd0_off = if little {
        u32::from_le_bytes(tiff[4..8].try_into().unwrap_or([0; 4]))
    } else {
        u32::from_be_bytes(tiff[4..8].try_into().unwrap_or([0; 4]))
    } as usize;
    walk_ifd(tiff, ifd0_off, little, st, true);
}

fn walk_ifd(tiff: &[u8], off: usize, little: bool, st: &mut JpegState, is_root: bool) {
    let read_u16 = |o: usize| -> Option<u16> {
        let b = tiff.get(o..o + 2)?.try_into().ok()?;
        Some(if little {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        })
    };
    let read_u32 = |o: usize| -> Option<u32> {
        let b = tiff.get(o..o + 4)?.try_into().ok()?;
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
        let entry_off = off + 2 + i * 12;
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
            tiff.get(abs..abs + total_bytes)
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
                    .saturating_add(total_bytes.min(u32::MAX as usize) as u32);
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
        extract(bytes, &mut v, &mut s, &mut m).unwrap();
        (v, m)
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
