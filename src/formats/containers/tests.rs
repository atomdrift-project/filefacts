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

/// `build_wav` in RIFX form: the same chunks with big-endian sizes.
fn build_rifx(extra: &[u8]) -> Vec<u8> {
    let fmt = [0u8, 1, 0, 1, 0, 0, 0x1f, 0x40, 0, 0, 0x1f, 0x40, 0, 1, 0, 8];
    let data = vec![0x80u8; 512];
    let mut body = Vec::from(*b"WAVE");
    body.extend_from_slice(b"fmt ");
    body.extend_from_slice(&(fmt.len() as u32).to_be_bytes());
    body.extend_from_slice(&fmt);
    body.extend_from_slice(b"data");
    body.extend_from_slice(&(data.len() as u32).to_be_bytes());
    body.extend_from_slice(&data);
    let mut out = Vec::from(*b"RIFX");
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(extra);
    out
}

/// RIFX sizes are big-endian. Read little-endian, a clean file's declared
/// length overran the input and its appended payload went unseen.
#[test]
fn rifx_sizes_are_big_endian() {
    let clean = build_rifx(&[]);
    let (v, m) = facts(&riff(&clean), &clean);
    assert_eq!(v.get("media.valid").and_then(|x| x.as_bool()), Some(true));
    assert_eq!(m.get("media.trailing_bytes"), Some(0.0));

    let stuffed = build_rifx(&fake_pe(4096));
    let (v, m) = facts(&riff(&stuffed), &stuffed);
    assert_eq!(stow(&v), vec!["pe"]);
    assert!(m.get("media.trailing_bytes").unwrap() > 4000.0);
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

#[test]
fn gif_unparsed_tail_does_not_imply_a_trailer() {
    let mut image = build_gif(&[]);
    // Abort at the image introducer, before any actual trailer.
    image[19] = 0x44;
    image.extend_from_slice(&fake_pe(1024));
    let (v, m) = facts(&gif(&image), &image);
    assert_eq!(v.get("media.valid").and_then(|x| x.as_bool()), Some(false));
    let problems = v.get("media.problems").unwrap().as_array().unwrap();
    assert!(
        problems
            .iter()
            .any(|x| x.as_str() == Some("unknown block marker"))
    );
    assert!(
        problems
            .iter()
            .any(|x| x.as_str() == Some("data beyond parsed container regions"))
    );
    assert!(
        !problems
            .iter()
            .any(|x| x.as_str() == Some("data appended after end of container"))
    );
    assert!(m.get("media.trailing_bytes").unwrap() > 1000.0);
    assert_eq!(stow(&v), vec!["pe"]);
}

#[test]
fn gif_metadata_payloads_are_inspected_without_claiming_concealment() {
    let clean = build_gif(&[]);
    for payload in [fake_pe(512), Vec::from(&b"ordinary metadata MZ"[..])] {
        let mut image = clean[..19].to_vec();
        image.extend_from_slice(&[0x21, 0xFE]);
        for chunk in payload.chunks(255) {
            image.push(chunk.len() as u8);
            image.extend_from_slice(chunk);
        }
        image.push(0);
        image.extend_from_slice(&clean[19..]);
        let (v, m) = facts(&gif(&image), &image);
        assert_eq!(v.get("media.valid").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(m.get("media.trailing_bytes"), Some(0.0));
        assert_eq!(m.get("media.stowaway_bytes"), Some(0.0));
        if payload.starts_with(b"MZ") {
            assert_eq!(stow(&v), vec!["pe"]);
        } else {
            assert!(stow(&v).is_empty());
        }
    }
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

/// The closing tag matches in any case, and the last one wins even when
/// the trailing bytes hold other `<` bytes or a truncated tag.
#[test]
fn svg_closing_tag_is_case_insensitive_and_last_wins() {
    let doc = b"<SVG><g></g></Svg><x></sVg>tail<</sv";
    let end = doc.windows(6).rposition(|w| w == b"</sVg>").unwrap() + 6;
    let claims: Vec<_> = svg(doc).claims.iter().map(|c| (c.start, c.end)).collect();
    assert_eq!(claims, vec![(0, end as u64)]);
}
