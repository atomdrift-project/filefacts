use super::*;

/// A 16-bit sample is two bytes: it sizes the decode at two bytes a
/// pixel and counts in the statistics by its high byte.
#[test]
fn sixteen_bit_samples_count_by_their_high_byte() {
    assert_eq!(jpeg_decoder::PixelFormat::L16.pixel_bytes(), 2);
    let decoded: Vec<u8> = [0x1234_u16, 0xff00]
        .iter()
        .flat_map(|s| s.to_ne_bytes())
        .collect();
    assert_eq!(
        eight_bit_samples(decoded, jpeg_decoder::PixelFormat::L16),
        [0x12, 0xff]
    );
    assert_eq!(
        eight_bit_samples(vec![1, 2, 3], jpeg_decoder::PixelFormat::RGB24),
        [1, 2, 3]
    );
}

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
    let (_, m) = run(&eob_run_scans(5_000));
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
fn restart_markers_keep_stuffed_bytes_inside_the_scan() {
    for restart in 0xD0..=0xD7 {
        let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xDA, 0, 8, 1, 1, 0, 0, 63, 0];
        jpeg.extend_from_slice(&[
            0x11, 0xFF, restart, 0x22, 0xFF, 0x00, 0xD9, 0x33, 0xFF, 0xD9,
        ]);
        jpeg.extend_from_slice(b"appended bytes");
        let (_, m) = run(&jpeg);
        assert_eq!(m.get("jpeg.trailing_bytes"), Some(14.0));
    }
}

#[test]
fn restarted_scan_without_eoi_does_not_invent_a_trailer() {
    let jpeg = [
        0xFF, 0xD8, 0xFF, 0xDA, 0, 8, 1, 1, 0, 0, 63, 0, 0x11, 0xFF, 0xD3, 0x22, 0xFF, 0x00, 0xD9,
        0x33,
    ];
    let (_, m) = run(&jpeg);
    assert_eq!(m.get("jpeg.trailing_bytes"), Some(0.0));
}

#[test]
fn restarted_scan_can_continue_into_another_scan() {
    let mut jpeg = vec![0xFF, 0xD8];
    for restart in [0xD0, 0xD7] {
        jpeg.extend_from_slice(&[0xFF, 0xDA, 0, 8, 1, 1, 0, 0, 63, 0]);
        jpeg.extend_from_slice(&[0x11, 0xFF, restart, 0xFF, 0x00, 0x22]);
    }
    jpeg.extend_from_slice(&[0xFF, 0xD9]);
    let (_, m) = run(&jpeg);
    assert_eq!(m.get("jpeg.trailing_bytes"), Some(0.0));
    assert_eq!(m.get("jpeg.segment_count"), Some(3.0));
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
/// extractor, not from the JPEG extractor; the full pipeline reports it,
/// decodable or not.
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
