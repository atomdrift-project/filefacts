//! PNG image extractor.
//!
//! Single linear pass over the PNG chunk table. We don't decompress
//! anything — IDAT bodies, zTXt zlib payloads, and iCCP profile
//! contents are skipped. Trait authors get the structural facts that
//! survive a no-zlib walk:
//!
//! - `png.dimensions.{width, height, bit_depth, color_type,
//!   interlace, filter, compression}` from `IHDR`.
//! - `png.text.<key>` for every `tEXt`/`iTXt` (uncompressed)
//!   key=value pair. `zTXt` keys land here too; values are blank
//!   pending a zlib pass.
//! - `png.time` — `tIME` timestamp formatted as ISO-8601.
//! - `png.icc_profile_name` from `iCCP`.
//! - `png.chunks[]` — every chunk type in document order (analyst
//!   gets to see the structural signature; valid PNGs follow a
//!   well-known sequence).
//! - `png.unknown_chunks[]` — chunk types outside the PNG/APNG
//!   standard set (steganography signal).
//! - `png.features[]` — Pike-style flag array for high-value
//!   presence signals: `apng`, `exif`, `icc`, `trailing_data`,
//!   `post_iend_chunks`.

use serde_json::{json, Value as JsonValue};

use crate::error::Error;
use crate::formats::common::extract_ascii_strings;
use crate::formats::image_stats;
use crate::output::{Metrics, Strings, Values};
use crate::scan::entropy;

const SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
) -> Result<(), Error> {
    extract_ascii_strings(bytes, strings);

    if bytes.len() < 8 || &bytes[..8] != SIGNATURE {
        return Ok(());
    }

    let mut chunks_total: usize = 0;
    let mut chunks_idat: usize = 0;
    let mut chunks_after_iend: usize = 0;
    let mut text_chunk_bytes: usize = 0;
    let mut unknown_count: usize = 0;
    let mut iend_seen = false;
    let mut last_chunk_end: usize = 8;

    let mut chunks: Vec<JsonValue> = Vec::new();
    let mut unknown_chunks: Vec<String> = Vec::new();
    let mut text_kv = serde_json::Map::new();
    let mut features: Vec<&'static str> = Vec::new();
    let mut dim_obj = serde_json::Map::new();
    let mut time_value: Option<String> = None;
    let mut icc_name: Option<String> = None;

    let mut i = 8usize;
    while i + 8 <= bytes.len() {
        let length =
            u32::from_be_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]) as usize;
        let ctype_bytes = &bytes[i + 4..i + 8];
        let body_start = i + 8;
        let Some(chunk_end) = body_start
            .checked_add(length)
            .and_then(|n| n.checked_add(4))
        else {
            break;
        };
        if chunk_end > bytes.len() {
            // Truncated — stop walking; keep counts so far.
            break;
        }
        last_chunk_end = chunk_end;

        let ctype = std::str::from_utf8(ctype_bytes).unwrap_or("");
        chunks_total += 1;
        if iend_seen {
            chunks_after_iend += 1;
        }
        if !ctype.is_empty() {
            chunks.push(JsonValue::String(ctype.to_string()));
        }

        let body = &bytes[body_start..body_start + length];
        match ctype {
            "IHDR" if body.len() >= 13 => {
                let width = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                let height = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
                dim_obj.insert("width".into(), json!(width));
                dim_obj.insert("height".into(), json!(height));
                dim_obj.insert("bit_depth".into(), json!(body[8]));
                dim_obj.insert(
                    "color_type".into(),
                    JsonValue::String(color_type_name(body[9]).to_string()),
                );
                dim_obj.insert("compression".into(), json!(body[10]));
                dim_obj.insert("filter".into(), json!(body[11]));
                dim_obj.insert(
                    "interlace".into(),
                    JsonValue::String(if body[12] == 1 { "adam7" } else { "none" }.to_string()),
                );
            }
            "IDAT" => chunks_idat += 1,
            "IEND" => iend_seen = true,
            "tEXt" | "zTXt" | "iTXt" => {
                text_chunk_bytes += length;
                if let Some((key, value)) = parse_text_chunk(ctype, body) {
                    text_kv.insert(snake_case(&key), JsonValue::String(value));
                }
            }
            "tIME" if body.len() >= 7 => {
                let year = u16::from_be_bytes([body[0], body[1]]);
                time_value = Some(format!(
                    "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                    year, body[2], body[3], body[4], body[5], body[6]
                ));
            }
            "iCCP" => {
                if let Some(end) = body.iter().position(|&b| b == 0) {
                    if let Ok(name) = std::str::from_utf8(&body[..end]) {
                        if !name.is_empty() {
                            icc_name = Some(name.to_string());
                        }
                    }
                }
                if !features.contains(&"icc") {
                    features.push("icc");
                }
            }
            "eXIf" => {
                if !features.contains(&"exif") {
                    features.push("exif");
                }
            }
            "acTL" | "fcTL" | "fdAT" => {
                if !features.contains(&"apng") {
                    features.push("apng");
                }
            }
            _ if !is_standard_chunk(ctype) => {
                if !ctype.is_empty() && !unknown_chunks.iter().any(|u| u == ctype) {
                    unknown_chunks.push(ctype.to_string());
                }
                unknown_count += 1;
            }
            _ => {}
        }

        i = chunk_end;
    }

    let trailing_bytes = bytes.len().saturating_sub(last_chunk_end);
    if trailing_bytes > 0 {
        features.push("trailing_data");
    }
    if chunks_after_iend > 0 {
        features.push("post_iend_chunks");
    }

    if !dim_obj.is_empty() {
        values.insert("png.dimensions", JsonValue::Object(dim_obj));
    }
    if !text_kv.is_empty() {
        values.insert("png.text", JsonValue::Object(text_kv));
    }
    if let Some(t) = time_value {
        // tIME chunk per PNG spec is the "last image modification time"
        // — match the archive/LNK `*_modified` / `mtime_*` convention
        // instead of a vague "time".
        values.insert("png.last_modified", JsonValue::String(t));
    }
    if let Some(n) = icc_name {
        values.insert("png.icc_profile_name", JsonValue::String(n));
    }
    if !chunks.is_empty() {
        values.insert("png.chunks", JsonValue::Array(chunks));
    }
    if !unknown_chunks.is_empty() {
        values.insert(
            "png.unknown_chunks",
            JsonValue::Array(unknown_chunks.into_iter().map(JsonValue::String).collect()),
        );
    }
    if !features.is_empty() {
        values.insert(
            "png.features",
            JsonValue::Array(
                features
                    .into_iter()
                    .map(|s| JsonValue::String(s.into()))
                    .collect(),
            ),
        );
    }

    metrics.insert("png.chunk_count", chunks_total as f64);
    metrics.insert("png.idat_chunk_count", chunks_idat as f64);
    metrics.insert("png.chunks_after_iend", chunks_after_iend as f64);
    metrics.insert("png.trailing_bytes", trailing_bytes as f64);
    metrics.insert("png.text_chunk_bytes", text_chunk_bytes as f64);
    metrics.insert("png.unknown_chunk_count", unknown_count as f64);

    // Best-effort pixel-statistic pass. Decoder errors are swallowed —
    // a PNG with a corrupted IDAT chunk or unsupported color depth
    // still gets the structural metrics above.
    extract_pixel_stats(bytes, metrics);

    Ok(())
}

/// Decode the PNG (cap-protected) and emit pixel-statistic metrics:
/// dimensions, per-channel entropy, edge density, histogram flatness,
/// compression ratio, and PNG-specific alpha entropy.
/// `binary.overall_entropy` is the Shannon entropy of the raw file
/// bytes — emitted unconditionally because it's cheap and useful even
/// when the pixel decode bails.
fn extract_pixel_stats(bytes: &[u8], metrics: &mut Metrics) {
    use png::Decoder;

    metrics.insert("binary.overall_entropy", entropy::shannon(bytes));

    let decoder = Decoder::new(bytes);
    let Ok(mut reader) = decoder.read_info() else {
        return;
    };
    let info = reader.info();
    let width = info.width;
    let height = info.height;
    let bit_depth = info.bit_depth as u32;
    let channels: u32 = match info.color_type {
        png::ColorType::Grayscale | png::ColorType::Indexed => 1,
        png::ColorType::GrayscaleAlpha => 2,
        png::ColorType::Rgb => 3,
        png::ColorType::Rgba => 4,
    };

    metrics.insert("image.width", f64::from(width));
    metrics.insert("image.height", f64::from(height));
    metrics.insert("image.channels", f64::from(channels));

    let buf_size = reader.output_buffer_size();
    if buf_size > image_stats::MAX_DECODE_BYTES {
        return;
    }
    let mut pixels = vec![0u8; buf_size];
    let Ok(output_info) = reader.next_frame(&mut pixels) else {
        return;
    };
    let pixels = &pixels[..output_info.buffer_size()];

    let raw_size = (width as usize)
        .saturating_mul(height as usize)
        .saturating_mul(channels as usize)
        .saturating_mul((bit_depth as usize / 8).max(1));
    let compression_ratio = if raw_size > 0 {
        bytes.len() as f64 / raw_size as f64
    } else {
        1.0
    };

    let pixel_entropy = entropy::shannon(pixels);
    metrics.insert("image.pixel_entropy", pixel_entropy);
    metrics.insert("image.histogram_flatness", pixel_entropy / 8.0);
    let density =
        image_stats::edge_density(pixels, width as usize, height as usize, channels as usize);
    metrics.insert("image.edge_density", f64::from(density));

    if channels >= 3 {
        let (r, g, b, a) = image_stats::channel_entropy(pixels, channels as usize);
        metrics.insert("image.r_entropy", f64::from(r));
        metrics.insert("image.g_entropy", f64::from(g));
        metrics.insert("image.b_entropy", f64::from(b));
        metrics.insert("png.a_entropy", f64::from(a));
    } else {
        // Mirror cleave's prior behavior: grayscale images put the
        // overall pixel entropy into `r_entropy` so traits keyed on
        // the red channel still fire for single-channel images.
        metrics.insert("image.r_entropy", pixel_entropy);
        metrics.insert("image.g_entropy", 0.0);
        metrics.insert("image.b_entropy", 0.0);
        metrics.insert("png.a_entropy", 0.0);
    }
    metrics.insert("png.compression_ratio", compression_ratio);
}

/// PNG-spec color-type byte → analyst-readable name. The canonical
/// strings (`grayscale`, `truecolor`, `palette`, `grayscale_alpha`,
/// `truecolor_alpha`) appear in libpng's own diagnostic output.
fn color_type_name(b: u8) -> &'static str {
    match b {
        0 => "grayscale",
        2 => "truecolor",
        3 => "palette",
        4 => "grayscale_alpha",
        6 => "truecolor_alpha",
        _ => "unknown",
    }
}

/// Standard PNG chunk types (PNG 1.2 spec + APNG + iCCP/eXIf
/// extensions). Anything outside this set surfaces in
/// `png.unknown_chunks` as a steganography / stowaway signal.
fn is_standard_chunk(t: &str) -> bool {
    matches!(
        t,
        "IHDR"
            | "IDAT"
            | "IEND"
            | "PLTE"
            | "tRNS"
            | "cHRM"
            | "gAMA"
            | "iCCP"
            | "sBIT"
            | "sRGB"
            | "tEXt"
            | "zTXt"
            | "iTXt"
            | "bKGD"
            | "hIST"
            | "pHYs"
            | "sPLT"
            | "tIME"
            | "eXIf"
            | "acTL"
            | "fcTL"
            | "fdAT"
    )
}

/// Parse the keyword + value out of any PNG text chunk variant.
/// All three (`tEXt`, `zTXt`, `iTXt`) start with a NUL-terminated
/// keyword; what follows differs. We surface the keyword always,
/// the text value only when it's uncompressed UTF-8.
fn parse_text_chunk(ctype: &str, body: &[u8]) -> Option<(String, String)> {
    let kw_end = body.iter().position(|&b| b == 0)?;
    let key = std::str::from_utf8(&body[..kw_end]).ok()?.to_string();
    let value = match ctype {
        "tEXt" => std::str::from_utf8(body.get(kw_end + 1..)?)
            .ok()?
            .to_string(),
        "zTXt" => String::new(), // zlib payload — decoded lazily later
        "iTXt" => {
            // `keyword\0 cflag(1) cmethod(1) language\0 translated_kw\0 text`.
            let cflag = *body.get(kw_end + 1)?;
            let after_meta = kw_end + 3;
            let rel_lang = body.get(after_meta..)?.iter().position(|&b| b == 0)?;
            let lang_end = after_meta + rel_lang;
            let trans_start = lang_end + 1;
            let rel_trans = body.get(trans_start..)?.iter().position(|&b| b == 0)?;
            let trans_end = trans_start + rel_trans;
            if cflag == 0 {
                std::str::from_utf8(body.get(trans_end + 1..)?)
                    .ok()?
                    .to_string()
            } else {
                String::new()
            }
        }
        _ => return None,
    };
    Some((key, value))
}

/// Convert a PNG text keyword (free-form, may contain spaces or
/// punctuation) into a snake_case path component. Standard keywords
/// (`Software`, `Author`, `Creation Time`) become `software`,
/// `author`, `creation_time`.
fn snake_case(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    let mut prev_upper = false;
    for ch in key.chars() {
        if ch.is_ascii_uppercase() {
            if !prev_upper && !out.is_empty() && !out.ends_with('_') {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
            prev_upper = true;
        } else if ch.is_ascii_alphanumeric() {
            out.push(ch);
            prev_upper = false;
        } else {
            if !out.is_empty() && !out.ends_with('_') {
                out.push('_');
            }
            prev_upper = false;
        }
    }
    out.trim_matches('_').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_png(chunks: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(SIGNATURE);
        for (ctype, body) in chunks {
            out.extend_from_slice(&(body.len() as u32).to_be_bytes());
            out.extend_from_slice(*ctype);
            out.extend_from_slice(body);
            out.extend_from_slice(&[0; 4]); // CRC (we don't check it)
        }
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
    fn parses_ihdr_dimensions() {
        let ihdr: Vec<u8> = vec![
            0, 0, 0, 100, // width=100
            0, 0, 0, 50, // height=50
            8,  // bit_depth
            2,  // color_type=truecolor
            0, 0, 1, // compression, filter, interlace=adam7
        ];
        let png = build_png(&[(b"IHDR", &ihdr), (b"IEND", &[])]);
        let (v, _) = run(&png);
        let dim = v.get("png.dimensions").and_then(|x| x.as_object()).unwrap();
        assert_eq!(dim.get("width").and_then(|x| x.as_u64()), Some(100));
        assert_eq!(dim.get("height").and_then(|x| x.as_u64()), Some(50));
        assert_eq!(
            dim.get("color_type").and_then(|x| x.as_str()),
            Some("truecolor")
        );
        assert_eq!(dim.get("interlace").and_then(|x| x.as_str()), Some("adam7"));
    }

    #[test]
    fn extracts_text_chunk() {
        let text = b"Software\0Adobe Photoshop";
        let png = build_png(&[(b"tEXt", text), (b"IEND", &[])]);
        let (v, _) = run(&png);
        assert_eq!(
            v.get("png.text.software").and_then(|x| x.as_str()),
            Some("Adobe Photoshop")
        );
    }

    #[test]
    fn flags_apng_and_icc() {
        let png = build_png(&[
            (b"iCCP", b"sRGB\0\0xxx"),
            (b"acTL", &[0; 8]),
            (b"IEND", &[]),
        ]);
        let (v, _) = run(&png);
        let feats = v.get("png.features").and_then(|x| x.as_array()).unwrap();
        let names: Vec<&str> = feats.iter().filter_map(|x| x.as_str()).collect();
        assert!(names.contains(&"icc"));
        assert!(names.contains(&"apng"));
        assert_eq!(
            v.get("png.icc_profile_name").and_then(|x| x.as_str()),
            Some("sRGB")
        );
    }

    #[test]
    fn detects_unknown_chunks() {
        let png = build_png(&[(b"sTeG", b"hidden"), (b"IEND", &[])]);
        let (v, _) = run(&png);
        let unk = v
            .get("png.unknown_chunks")
            .and_then(|x| x.as_array())
            .unwrap();
        assert_eq!(unk.len(), 1);
        assert_eq!(unk[0].as_str(), Some("sTeG"));
    }

    #[test]
    fn detects_trailing_bytes() {
        let mut png = build_png(&[(b"IEND", &[])]);
        png.extend_from_slice(b"stowaway data");
        let (v, m) = run(&png);
        let feats = v.get("png.features").and_then(|x| x.as_array()).unwrap();
        let names: Vec<&str> = feats.iter().filter_map(|x| x.as_str()).collect();
        assert!(names.contains(&"trailing_data"));
        assert!(m.get("png.trailing_bytes").unwrap() > 0.0);
    }

    #[test]
    fn no_signature_is_silent() {
        let (v, _) = run(b"not a png");
        assert!(v.get("png.dimensions").is_none());
    }

    #[test]
    fn truncated_chunk_length_doesnt_crash() {
        // Signature plus a length that overruns the buffer.
        let mut png = Vec::new();
        png.extend_from_slice(SIGNATURE);
        png.extend_from_slice(&999_999u32.to_be_bytes());
        png.extend_from_slice(b"IDAT");
        let (v, _) = run(&png);
        // Should not panic; no IHDR was emitted.
        assert!(v.get("png.dimensions").is_none());
    }

    #[test]
    fn empty_input_is_silent() {
        let (v, _) = run(&[]);
        assert!(v.get("png.dimensions").is_none());
    }

    #[test]
    fn chunk_metrics_count_correctly() {
        let ihdr: Vec<u8> = vec![0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0];
        let png = build_png(&[
            (b"IHDR", &ihdr),
            (b"IDAT", &[0; 4]),
            (b"IDAT", &[0; 4]),
            (b"IDAT", &[0; 4]),
            (b"IEND", &[]),
        ]);
        let (_, m) = run(&png);
        assert_eq!(m.get("png.idat_chunk_count"), Some(3.0));
        assert_eq!(m.get("png.chunk_count"), Some(5.0));
        assert_eq!(m.get("png.chunks_after_iend"), Some(0.0));
    }

    #[test]
    fn chunks_after_iend_counted() {
        let png = build_png(&[
            (b"IEND", &[]),
            // tEXt chunk after IEND — should bump chunks_after_iend.
            (b"tEXt", b"k\0v"),
        ]);
        let (_, m) = run(&png);
        assert_eq!(m.get("png.chunks_after_iend"), Some(1.0));
    }

    #[test]
    fn text_chunk_bytes_metric_accumulates() {
        let png = build_png(&[
            (b"tEXt", b"k1\0value-one"),
            (b"tEXt", b"k2\0value-two"),
            (b"IEND", &[]),
        ]);
        let (_, m) = run(&png);
        let bytes = m.get("png.text_chunk_bytes").unwrap();
        assert!(bytes > 0.0);
    }

    /// Encode a real RGB PNG via the `png` crate so the pixel-stat
    /// decode path runs end-to-end. Constant-color image → zero pixel
    /// entropy, zero edge density, low histogram flatness.
    fn encode_rgb_png(width: u32, height: u32, fill: [u8; 3]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut enc = png::Encoder::new(&mut out, width, height);
            enc.set_color(png::ColorType::Rgb);
            enc.set_depth(png::BitDepth::Eight);
            let mut writer = enc.write_header().unwrap();
            let mut pixels = Vec::with_capacity((width * height * 3) as usize);
            for _ in 0..(width * height) {
                pixels.extend_from_slice(&fill);
            }
            writer.write_image_data(&pixels).unwrap();
        }
        out
    }

    #[test]
    fn pixel_stats_constant_rgb_image() {
        let png = encode_rgb_png(16, 16, [128, 128, 128]);
        let (_, m) = run(&png);
        assert_eq!(m.get("image.width"), Some(16.0));
        assert_eq!(m.get("image.height"), Some(16.0));
        assert_eq!(m.get("image.channels"), Some(3.0));
        // Constant image — pixel entropy is exactly 0 bits/byte.
        let pe = m.get("image.pixel_entropy").unwrap();
        assert!(pe.abs() < 1e-6, "expected ~0 entropy, got {pe}");
        let ed = m.get("image.edge_density").unwrap();
        assert!(ed.abs() < 1e-6, "expected ~0 edge density, got {ed}");
        // Histogram flatness is just pixel_entropy / 8.
        let hf = m.get("image.histogram_flatness").unwrap();
        assert!(hf.abs() < 1e-6);
        // Channel-entropy fields are populated.
        assert!(m.get("image.r_entropy").is_some());
        assert!(m.get("image.g_entropy").is_some());
        assert!(m.get("image.b_entropy").is_some());
        // Compression ratio defined (real PNG > raw size for tiny imgs).
        assert!(m.get("png.compression_ratio").unwrap() > 0.0);
        // No alpha channel — a_entropy stays 0.
        assert_eq!(m.get("png.a_entropy"), Some(0.0));
        // binary.overall_entropy emitted as Shannon of raw file bytes.
        assert!(m.get("binary.overall_entropy").unwrap() > 0.0);
    }

    #[test]
    fn pixel_stats_natural_image_has_nonzero_entropy() {
        let mut out = Vec::new();
        {
            let mut enc = png::Encoder::new(&mut out, 32, 32);
            enc.set_color(png::ColorType::Rgb);
            enc.set_depth(png::BitDepth::Eight);
            let mut writer = enc.write_header().unwrap();
            let mut pixels = Vec::with_capacity(32 * 32 * 3);
            // Deterministic pseudo-random pattern with structure
            // (gradient + noise) — non-trivial entropy, some edges.
            for y in 0..32u32 {
                for x in 0..32u32 {
                    pixels.push(((x * 8 + y * 3) % 256) as u8);
                    pixels.push(((x * 5 + y * 11) % 256) as u8);
                    pixels.push(((x * 13 + y * 7) % 256) as u8);
                }
            }
            writer.write_image_data(&pixels).unwrap();
        }
        let (_, m) = run(&out);
        let pe = m.get("image.pixel_entropy").unwrap();
        assert!(pe > 1.0, "expected significant entropy, got {pe}");
        let r = m.get("image.r_entropy").unwrap();
        let g = m.get("image.g_entropy").unwrap();
        let b = m.get("image.b_entropy").unwrap();
        assert!(r > 0.0 && g > 0.0 && b > 0.0);
    }

    #[test]
    fn malformed_png_decode_still_emits_binary_entropy() {
        // Valid PNG signature + IHDR claiming a width that overruns
        // the IDAT stream. Decode fails; binary.overall_entropy still
        // emits because it doesn't depend on the decoder.
        let ihdr = vec![0, 0, 0, 100, 0, 0, 0, 100, 8, 2, 0, 0, 0];
        let png = build_png(&[(b"IHDR", &ihdr), (b"IDAT", &[0; 4]), (b"IEND", &[])]);
        let (_, m) = run(&png);
        assert!(m.get("binary.overall_entropy").is_some());
    }
}
