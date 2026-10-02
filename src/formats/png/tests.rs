use super::*;

fn build_png(chunks: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(SIGNATURE);
    for (ctype, body) in chunks {
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(*ctype);
        out.extend_from_slice(body);
        let mut crc = crc32fast::Hasher::new();
        crc.update(*ctype);
        crc.update(body);
        out.extend_from_slice(&crc.finalize().to_be_bytes());
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
fn c2pa_chunk_is_claimed_metadata_not_an_interior_hole() {
    let mut manifest = b"\0\0\0\x14jumbc2pa metadata".to_vec();
    manifest.resize(4096, b' ');
    let png = build_png(&[(b"caBX", &manifest), (b"IEND", &[])]);
    let (v, m) = run(&png);
    assert_eq!(m.get("png.unknown_chunk_count"), Some(0.0));
    assert!(v.get("png.unknown_chunks").is_none());
    assert_eq!(m.get("media.gap_bytes"), Some(0.0));
    assert_eq!(m.get("media.stowaway_bytes"), Some(0.0));
    assert!(v.get("media.stowaway").is_none());
    assert!(
        v.get("png.chunks")
            .unwrap()
            .as_array()
            .unwrap()
            .contains(&json!("caBX"))
    );
}

#[test]
fn c2pa_chunk_does_not_hide_an_embedded_executable() {
    let mut payload = vec![0; 512];
    payload[..2].copy_from_slice(b"MZ");
    payload[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    payload[0x40..0x44].copy_from_slice(b"PE\0\0");
    let png = build_png(&[(b"caBX", &payload), (b"IEND", &[])]);
    let (v, m) = run(&png);
    assert_eq!(m.get("media.gap_bytes"), Some(0.0));
    assert!(
        v.get("media.stowaway")
            .unwrap()
            .as_array()
            .unwrap()
            .contains(&json!("pe"))
    );
}

#[test]
fn c2pa_chunk_does_not_claim_neighboring_unknown_chunks_or_trailers() {
    let hidden = vec![b'X'; 1024];
    let mut png = build_png(&[(b"caBX", b"provenance"), (b"sTeG", &hidden), (b"IEND", &[])]);
    png.extend_from_slice(&hidden);
    let (v, m) = run(&png);
    assert_eq!(m.get("png.unknown_chunk_count"), Some(1.0));
    assert_eq!(v.get("png.unknown_chunks"), Some(&json!(["sTeG"])));
    assert!(m.get("media.gap_bytes").unwrap() >= 1024.0);
    assert!(m.get("media.trailing_bytes").unwrap() >= 1000.0);
}

fn ninepatch_body(x: u8, y: u8, colors: u8) -> Vec<u8> {
    let mut body = vec![0u8; 32 + 4 * (x as usize + y as usize + colors as usize)];
    body[0] = 1;
    body[1] = x;
    body[2] = y;
    body[3] = colors;
    body
}

#[test]
fn aapt_ninepatch_chunks_are_claimed_structure() {
    let np_tc = ninepatch_body(2, 2, 9);
    let png = build_png(&[
        (b"npOl", &[0u8; 24]),
        (b"npTc", &np_tc),
        (b"npLb", &[0u8; 16]),
        (b"IEND", &[]),
    ]);
    let (v, m) = run(&png);
    // Still reported as non-standard chunk types...
    assert_eq!(m.get("png.unknown_chunk_count"), Some(3.0));
    assert!(v.get("png.unknown_chunks").is_some());
    // ...but not as unaccounted-for bytes.
    assert_eq!(m.get("media.gap_bytes"), Some(0.0));
    assert_eq!(m.get("media.stowaway_bytes"), Some(0.0));
}

#[test]
fn payload_named_nptc_is_still_a_hole() {
    // Right name, wrong shape: counts claim 13 entries but the body is 1 KiB.
    let mut body = ninepatch_body(2, 2, 9);
    body.resize(1024, b'X');
    let png = build_png(&[(b"npTc", &body), (b"IEND", &[])]);
    let (_, m) = run(&png);
    assert!(m.get("media.gap_bytes").unwrap() >= 1024.0);
}

#[test]
fn nptc_with_bad_crc_is_still_a_hole() {
    let body = ninepatch_body(2, 2, 9);
    let mut png = build_png(&[(b"npTc", &body), (b"IEND", &[])]);
    // Flip one CRC byte of the npTc chunk (8 sig + 8 header + body).
    let crc_at = 8 + 8 + body.len();
    png[crc_at] ^= 0xff;
    let (_, m) = run(&png);
    assert!(m.get("media.gap_bytes").unwrap() >= body.len() as f64);
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
    assert_eq!(m.get("png.trailing_chunk_count"), Some(0.0));
}

#[test]
fn idat_payload_after_zlib_stream_is_stowaway() {
    use std::io::Write;

    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(b"\0rendered pixels").unwrap();
    let compressed = encoder.finish().unwrap();
    let split = compressed.len() / 2;
    let hidden: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
    let mut final_idat = compressed[split..].to_vec();
    final_idat.extend_from_slice(&hidden);
    let png = build_png(&[
        (b"IDAT", &compressed[..split]),
        (b"IDAT", &final_idat),
        (b"IEND", &[]),
    ]);

    let (v, m) = run(&png);
    assert_eq!(
        m.get("png.idat_bytes"),
        Some((compressed.len() + hidden.len()) as f64)
    );
    assert_eq!(m.get("png.idat_zlib_bytes"), Some(compressed.len() as f64));
    assert_eq!(m.get("png.idat_unused_bytes"), Some(hidden.len() as f64));
    assert_eq!(m.get("media.stowaway_bytes"), Some(hidden.len() as f64));
    assert_eq!(m.get("media.gap_bytes"), Some(hidden.len() as f64));
    assert_eq!(v.get("media.stowaway"), Some(&json!(["high_entropy"])));
    assert_eq!(v.get("media.valid"), Some(&json!(false)));
}

#[test]
fn chunks_after_iend_counted() {
    let png = build_png(&[
        (b"IEND", &[]),
        // tEXt chunk after IEND — should bump chunks_after_iend.
        (b"tEXt", b"k\0v"),
    ]);
    let (_, m) = run(&png);
    assert_eq!(m.get("png.trailing_chunk_count"), Some(1.0));
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

/// `file.entropy` comes from the generic pass that runs ahead of every
/// extractor, so the PNG extractor no longer computes it a second time;
/// the full pipeline still reports it, decodable or not.
#[test]
fn file_entropy_comes_from_the_generic_pass() {
    // Valid PNG signature + IHDR claiming a width that overruns
    // the IDAT stream, so the pixel decode fails.
    let ihdr = vec![0, 0, 0, 100, 0, 0, 0, 100, 8, 2, 0, 0, 0];
    let broken = build_png(&[(b"IHDR", &ihdr), (b"IDAT", &[0; 4]), (b"IEND", &[])]);
    let (_, m) = run(&broken);
    assert!(m.get("file.entropy").is_none());

    for bytes in [broken, encode_rgb_png(16, 16, [128, 128, 128])] {
        let parsed = crate::OpenOptions::new()
            .path(std::path::Path::new("x.png"))
            .open(&bytes);
        assert_eq!(parsed.fileid().file_type(), crate::FileType::Png);
        let h = parsed.metrics().get("file.entropy").unwrap();
        assert!((h - entropy::shannon(&bytes)).abs() < 1e-9);
    }
}
