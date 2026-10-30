//! Bounded reconstruction of simple payload encodings in decoded PNG samples.
//!
//! Reconstructed bytes have no contiguous source-file span. Their format,
//! layout and bounded preview are format-derived values, not source literals.
//! Random-looking pixels alone are never treated as a recovered payload.

use std::collections::BTreeSet;
use std::io::Read;
use std::sync::LazyLock;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use flate2::{Decompress, FlushDecompress, Status};
use regex::Regex;
use serde_json::{Value, json};

use crate::formats::bounded::Limits;
use crate::output::{Metrics, Values};
use crate::{metric, value_key};

const PREFIX_BYTES: usize = 4096;
const SEARCH_BYTES: usize = 512;
const MAX_DECODED: usize = 64 * 1024;
const MAX_PIXELS: usize = 262_144;
const MAX_STEPS: usize = 20 * 1024 * 1024;
const MAX_PAYLOADS: usize = 16;
const MAX_PREVIEW: usize = 2048;
const MASKS: [u8; 12] = [255, 1, 2, 3, 7, 15, 4, 8, 16, 32, 64, 128];

static CODE_PREFIXES: LazyLock<aho_corasick::AhoCorasick> = LazyLock::new(|| {
    aho_corasick::AhoCorasick::new([
        "#!/",
        "curl ",
        "wget ",
        "printf ",
        "echo ",
        "import ",
        "from ",
        "const ",
        "var ",
        "function ",
        "powershell",
        "Invoke-",
        "IEX",
        "$",
        "[Convert]",
    ])
    .expect("constant code prefixes")
});

static PIXEL_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)^https?://(?:[a-z0-9-]+\.)+[a-z0-9-]+(?::[0-9]{1,5})?(?:/[^\s\x00"<>]*)?"#)
        .expect("constant pixel URL regex")
});

static SHEBANG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^#![^\r\n]{0,120}\b(sh|bash|dash|ksh|zsh|python[0-9.]*|node)\b")
        .expect("constant shebang regex")
});
static SHELL_COMMAND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?m)(?:^|[;\n])[ \t]*(?:printf|echo|id|uname|curl|wget|exec|chmod|bash|sh)(?:[ \t]|$)",
    )
    .expect("constant shell-command regex")
});
static POWERSHELL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:Invoke-[A-Z]+|Start-Process|New-Object|FromBase64String|powershell(?:\.exe)?|IEX)\b")
        .expect("constant PowerShell regex")
});

#[derive(Default)]
struct Probe {
    steps: usize,
    count: usize,
    bytes: usize,
    limited: bool,
    found: Vec<Value>,
    seen: BTreeSet<(String, String)>,
}

impl Probe {
    fn inspect(&mut self, bytes: &[u8], layout: &str) {
        self.count += 1;
        self.bytes += bytes.len();
        if self.found.len() >= MAX_PAYLOADS {
            self.limited = true;
            return;
        }
        let mut candidates = vec![(bytes.to_vec(), "raw".to_string(), 0)];
        let mut at = 0;
        // At most two encoding layers and eight candidate buffers per probe.
        while at < candidates.len() && at < 8 {
            let (data, encoding, depth) = candidates.get(at).cloned().unwrap_or_default();
            at += 1;
            if let Some((kind, preview)) = content(&data)
                && self.seen.insert((kind.to_string(), preview.clone()))
            {
                self.found.push(
                    json!({"kind":kind,"layout":layout,"encoding":encoding,"preview":preview}),
                );
                if self.found.len() >= MAX_PAYLOADS {
                    self.limited = true;
                    break;
                }
            }
            if depth >= 2 {
                continue;
            }
            // Cheap single-byte XOR recovery uses a complete known prefix,
            // not 256 speculative decodes of every candidate stream.
            if depth == 0 {
                for offset in [0, 4, 8, 16] {
                    let rest = data.get(offset..).unwrap_or_default();
                    for prefix in [
                        b"#!/".as_slice(),
                        b"\x7fELF",
                        b"import ",
                        b"const ",
                        b"powershell",
                    ] {
                        let Some((&first, expected)) = rest.first().zip(prefix.first()) else {
                            continue;
                        };
                        let key = first ^ expected;
                        if key != 0
                            && rest.get(..prefix.len()).is_some_and(|head| {
                                head.iter().zip(prefix).all(|(&a, &b)| a ^ key == b)
                            })
                        {
                            candidates.push((
                                rest.iter().map(|b| b ^ key).collect(),
                                format!("{encoding}/xor-{key:02x}"),
                                depth + 1,
                            ));
                        }
                    }
                }
            }
            let body = framed_body(&data).unwrap_or(&data);
            let text = body
                .split(|&b| b == 0 || b.is_ascii_whitespace())
                .next()
                .unwrap_or_default();
            if text.len() >= 32
                && text
                    .iter()
                    .all(|&b| b.is_ascii_alphanumeric() || b"+/=_-".contains(&b))
            {
                for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
                    if let Ok(decoded) = engine.decode(text) {
                        candidates.push((decoded, format!("{encoding}/base64"), depth + 1));
                        break;
                    }
                }
            }
            if text.len() >= 64
                && text.len().is_multiple_of(2)
                && text.iter().all(u8::is_ascii_hexdigit)
            {
                let decoded: Option<Vec<_>> = text
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| {
                        let pair = std::str::from_utf8(pair).ok()?;
                        u8::from_str_radix(pair, 16).ok()
                    })
                    .collect();
                if let Some(decoded) = decoded {
                    candidates.push((decoded, format!("{encoding}/hex"), depth + 1));
                }
            }
            for (offset, _) in body
                .iter()
                .take(SEARCH_BYTES)
                .enumerate()
                .filter(|(_, b)| matches!(**b, 0x78 | 0x1f))
            {
                let rest = body.get(offset..).unwrap_or_default();
                if let Some(decoded) = decompress(rest) {
                    candidates.push((decoded, format!("{encoding}/zlib-or-gzip"), depth + 1));
                    break;
                }
            }
            for little in [true, false] {
                let prefix = body.get(..body.len().min(128)).unwrap_or(body);
                if prefix.iter().filter(|&&b| b == 0).count() < 16 {
                    continue;
                }
                let skip =
                    usize::from(body.starts_with(&[0xff, 0xfe]) || body.starts_with(&[0xfe, 0xff]))
                        * 2;
                let units: Vec<_> = body
                    .get(skip..)
                    .unwrap_or_default()
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|p| {
                        if little {
                            u16::from_le_bytes(*p)
                        } else {
                            u16::from_be_bytes(*p)
                        }
                    })
                    .take_while(|&v| v != 0)
                    .collect();
                if let Ok(decoded) = String::from_utf16(&units) {
                    candidates.push((
                        decoded.into_bytes(),
                        format!("{encoding}/utf16{}", if little { "le" } else { "be" }),
                        depth + 1,
                    ));
                }
            }
            candidates.truncate(8);
        }
    }
}

fn decompress(data: &[u8]) -> Option<Vec<u8>> {
    if data.starts_with(&[0x1f, 0x8b, 8]) {
        let mut output = Vec::new();
        flate2::read::GzDecoder::new(data)
            .take((MAX_DECODED + 1) as u64)
            .read_to_end(&mut output)
            .ok()?;
        return (output.len() <= MAX_DECODED && output.len() >= 32).then_some(output);
    }
    let header = data.first_chunk::<2>()?;
    if header[0] != 0x78 || u16::from_be_bytes(*header) % 31 != 0 {
        return None;
    }
    let mut output = Vec::with_capacity(MAX_DECODED);
    let status = Decompress::new(true)
        .decompress_vec(data, &mut output, FlushDecompress::Finish)
        .ok()?;
    (status == Status::StreamEnd && output.len() >= 32).then_some(output)
}

fn framed_body(bytes: &[u8]) -> Option<&[u8]> {
    let colon = bytes.iter().take(10).position(|&b| b == b':')?;
    let digits = bytes.get(..colon)?;
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let len: usize = std::str::from_utf8(digits).ok()?.parse().ok()?;
    (len >= 32).then_some(())?;
    bytes.get(colon + 1..colon.checked_add(1)?.checked_add(len)?)
}

fn content(data: &[u8]) -> Option<(&'static str, String)> {
    // Header offsets are limited to simple length/padding prefixes. All
    // goblin calls use the shared panic-safe, allocation-bounded wrappers.
    for offset in [0, 4, 8, 16] {
        let bytes = data.get(offset..).unwrap_or_default();
        if matches!(bytes.first(), Some(b'{' | b'[')) {
            let mut parsed = serde_json::Deserializer::from_slice(bytes).into_iter::<Value>();
            if let Some(Ok(value)) = parsed.next()
                && (value.as_object().is_some_and(|v| !v.is_empty())
                    || value.as_array().is_some_and(|v| !v.is_empty()))
                && parsed.byte_offset() >= 32
            {
                return Some((
                    "json",
                    String::from_utf8_lossy(bytes.get(..parsed.byte_offset()).unwrap_or_default())
                        .chars()
                        .take(MAX_PREVIEW)
                        .collect(),
                ));
            }
        }
        if bytes.starts_with(b"http") {
            let run = bytes.split(|&b| b == 0).next().unwrap_or_default();
            if let Ok(text) = std::str::from_utf8(run)
                && let Some(url) = PIXEL_URL.find(text)
                && url.len() >= 16
            {
                return Some(("url", url.as_str().chars().take(MAX_PREVIEW).collect()));
            }
        }
        if bytes.starts_with(b"MZ") {
            if super::goblin_safe::parse_pe(&super::goblin_safe::prepare_pe(bytes))
                .ok()
                .is_some()
            {
                return Some(("pe", String::new()));
            }
            if super::goblin_safe::parse_pe_header(bytes)
                .ok()
                .is_some_and(|h| {
                    h.signature == 0x4550
                        && (1..=96).contains(&h.coff_header.number_of_sections)
                        && h.optional_header.is_some()
                })
            {
                return Some(("pe-header", String::new()));
            }
        }
        if bytes.starts_with(b"\x7fELF") {
            if super::goblin_safe::parse_elf(bytes).ok().is_some() {
                return Some(("elf", String::new()));
            }
            let header_ok = match bytes.get(4) {
                Some(1) => {
                    super::goblin_safe::catch(|| goblin::elf32::header::Header::parse(bytes))
                        .ok()
                        .is_some_and(|h| {
                            matches!(h.e_type, 2 | 3)
                                && h.e_ehsize >= 52
                                && h.e_version == 1
                                && h.e_machine != 0
                        })
                }
                Some(2) => {
                    super::goblin_safe::catch(|| goblin::elf64::header::Header::parse(bytes))
                        .ok()
                        .is_some_and(|h| {
                            matches!(h.e_type, 2 | 3)
                                && h.e_ehsize >= 64
                                && h.e_version == 1
                                && h.e_machine != 0
                        })
                }
                _ => false,
            };
            if header_ok {
                return Some(("elf-header", String::new()));
            }
        }
        if bytes.starts_with(b"PK\x03\x04") && valid_zip(bytes) {
            return Some(("zip", String::new()));
        }
    }
    let framed = framed_body(data);
    let body = framed.unwrap_or(data);
    let bytes = body.get(..body.len().min(PREFIX_BYTES)).unwrap_or(body);
    // Length fields and short padding may precede a script. A printable run
    // must be long enough and carry syntax; generic English and flat pixels
    // are not recovered-code evidence.
    let prefix = bytes.get(..bytes.len().min(SEARCH_BYTES)).unwrap_or(bytes);
    for found in CODE_PREFIXES.find_iter(prefix).take(16) {
        let rest = bytes.get(found.start()..)?;
        let run_len = rest
            .iter()
            .take_while(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
            .count();
        if run_len < 32 {
            continue;
        }
        let text = std::str::from_utf8(rest.get(..run_len)?).ok()?;
        let first_line = text.lines().next().unwrap_or_default();
        let shebang = SHEBANG.find(first_line).map(|m| m.as_str());
        let kind = if shebang.is_some_and(|s| s.contains("python")) {
            Some("python")
        } else if shebang.is_some_and(|s| s.contains("node")) {
            Some("javascript")
        } else if shebang.is_some()
            || SHELL_COMMAND.find_iter(text).take(2).count() == 2
            || ((text.starts_with("curl ") || text.starts_with("wget "))
                && (text.contains("| sh") || text.contains("|sh") || text.contains("| bash")))
        {
            Some("shell")
        } else if POWERSHELL.is_match(text)
            && (text.contains('$') || text.contains(" -") || text.contains('('))
        {
            Some("powershell")
        } else if (text.starts_with("import ") || text.starts_with("from "))
            && (text.contains("\ndef ") || text.contains(".system(") || text.contains("exec("))
        {
            Some("python")
        } else if (text.starts_with("const ")
            || text.starts_with("var ")
            || text.starts_with("function "))
            && (text.contains("require(") || text.contains("=>") || text.contains("function("))
        {
            Some("javascript")
        } else {
            None
        };
        if let Some(kind) = kind {
            return Some((kind, text.chars().take(MAX_PREVIEW).collect()));
        }
    }
    if let Some(body) = framed
        && body
            .iter()
            .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        && body.iter().copied().collect::<BTreeSet<_>>().len() >= 12
        && body
            .split(u8::is_ascii_whitespace)
            .filter(|w| !w.is_empty())
            .count()
            >= 3
    {
        return Some((
            "framed-text",
            String::from_utf8_lossy(body)
                .chars()
                .take(MAX_PREVIEW)
                .collect(),
        ));
    }
    None
}

fn valid_zip(bytes: &[u8]) -> bool {
    let Some(eocd) = bytes.windows(4).rposition(|w| w == b"PK\x05\x06") else {
        return false;
    };
    let Some(count) = bytes
        .get(eocd + 10..eocd + 12)
        .and_then(|p| p.first_chunk::<2>())
    else {
        return false;
    };
    // A tiny recovered ZIP need not allocate a directory for thousands of
    // forged entries; complete ordinary archives still use the regular parser.
    let count = u16::from_le_bytes(*count);
    count > 0
        && count <= 256
        && zip::ZipArchive::new(std::io::Cursor::new(bytes)).is_ok_and(|a| !a.is_empty())
}

fn prime_sieve(size: usize) -> Vec<bool> {
    let mut primes = vec![true; size];
    for index in [0, 1] {
        if let Some(v) = primes.get_mut(index) {
            *v = false;
        }
    }
    for p in 2..size {
        if p > size / p {
            break;
        }
        if primes.get(p).copied().unwrap_or(false) {
            for at in (p * p..size).step_by(p) {
                if let Some(v) = primes.get_mut(at) {
                    *v = false;
                }
            }
        }
    }
    primes
}

#[derive(Clone, Copy)]
struct PixelView<'a> {
    pixels: &'a [u8],
    width: usize,
    height: usize,
    channels: usize,
}

#[derive(Clone, Copy)]
struct Packing<'a> {
    offsets: &'a [usize],
    column: bool,
    prime: Option<&'a [usize]>,
    flip_x: bool,
    flip_y: bool,
    cap: usize,
    mask: u8,
    reverse: bool,
}

fn bitstream(view: PixelView<'_>, packing: Packing<'_>, probe: &mut Probe) -> Vec<u8> {
    let PixelView {
        pixels,
        width,
        height,
        channels,
    } = view;
    let Packing {
        offsets,
        column,
        prime,
        mask,
        reverse,
        flip_x,
        flip_y,
        cap,
    } = packing;
    let total = width.saturating_mul(height);
    let mut out = Vec::with_capacity(cap);
    let (mut byte, mut used) = (0u8, 0u8);
    let ordinary = 0..if prime.is_none() {
        total.min(MAX_PIXELS)
    } else {
        0
    };
    for index in ordinary.chain(prime.unwrap_or_default().iter().copied()) {
        probe.steps += 1;
        if probe.steps > MAX_STEPS {
            probe.limited = true;
            break;
        }
        let (x, y) = if column {
            (index / height, index % height)
        } else {
            (index % width, index / width)
        };
        let x = if flip_x { width - 1 - x } else { x };
        let y = if flip_y { height - 1 - y } else { y };
        let pixel = y * width + x;
        for offset in offsets {
            let Some(&value) = pixels.get(pixel.saturating_mul(channels).saturating_add(*offset))
            else {
                return out;
            };
            for bit in (0..8).rev().filter(|&b| mask & (1 << b) != 0) {
                let value = (value >> bit) & 1;
                if reverse {
                    byte |= value << used;
                } else {
                    byte = (byte << 1) | value;
                }
                used += 1;
                if used == 8 {
                    out.push(byte);
                    byte = 0;
                    used = 0;
                    if out.len() == cap {
                        probe.limited |= index + 1 < total;
                        return out;
                    }
                }
            }
        }
    }
    probe.limited |= total > MAX_PIXELS;
    out
}

/// Probe prefixes from decoded 8-bit samples, preserving the pixel layout.
pub(super) fn extract(
    pixels: &[u8],
    width: usize,
    height: usize,
    channels: usize,
    lane: &str,
    values: &mut Values,
    metrics: &mut Metrics,
) {
    if width == 0 || height == 0 || !(1..=4).contains(&channels) {
        return;
    }
    if width
        .checked_mul(height)
        .and_then(|v| v.checked_mul(channels))
        != Some(pixels.len())
    {
        let mut limits = Limits::default();
        limits.push(
            "pixel-payloads",
            "decoded sample count does not match image dimensions",
        );
        limits.emit(values, value_key!("png.limits"));
        return;
    }
    let layouts: &[(&str, &[usize])] = match channels {
        1 => &[("gray", &[0])],
        2 => &[
            ("gray", &[0]),
            ("a", &[1]),
            ("gray-a", &[0, 1]),
            ("a-gray", &[1, 0]),
        ],
        3 => &[
            ("rgb", &[0, 1, 2]),
            ("bgr", &[2, 1, 0]),
            ("r", &[0]),
            ("g", &[1]),
            ("b", &[2]),
        ],
        _ => &[
            ("rgb", &[0, 1, 2]),
            ("bgr", &[2, 1, 0]),
            ("rgba", &[0, 1, 2, 3]),
            ("abgr", &[3, 2, 1, 0]),
            ("r", &[0]),
            ("g", &[1]),
            ("b", &[2]),
            ("a", &[3]),
        ],
    };
    let primes: Vec<usize> = prime_sieve(width.saturating_mul(height).min(MAX_PIXELS))
        .into_iter()
        .enumerate()
        .filter_map(|(index, yes)| yes.then_some(index))
        .collect();
    let mut probe = Probe::default();
    if channels == 4 {
        let hidden: Vec<u8> = pixels
            .as_chunks::<4>()
            .0
            .iter()
            .take(MAX_PIXELS)
            .filter(|p| p.get(3) == Some(&0))
            .flat_map(|p| p.get(..3).unwrap_or_default().iter().copied())
            .take(PREFIX_BYTES)
            .collect();
        probe.inspect(&hidden, &format!("{lane}/transparent-rgb"));
    }
    // Short prefixes cover all eight elementary spatial directions first.
    // Longer probes prioritize the common row/column walks. Iterating a
    // precomputed prime-index list avoids charging every skipped pixel on
    // every channel/bit-plane combination.
    'probes: for cap in [512, PREFIX_BYTES] {
        for (column, flip_x, flip_y) in [
            (false, false, false),
            (true, false, false),
            (false, true, true),
            (true, true, true),
            (false, true, false),
            (true, false, true),
            (false, false, true),
            (true, true, false),
        ] {
            if cap == PREFIX_BYTES && (flip_x || flip_y) {
                continue;
            }
            for prime in [false, true] {
                for &(name, offsets) in layouts {
                    for mask in MASKS {
                        for reverse in [false, true] {
                            if probe.steps >= MAX_STEPS || probe.found.len() >= MAX_PAYLOADS {
                                probe.limited = true;
                                break 'probes;
                            }
                            let data = bitstream(
                                PixelView {
                                    pixels,
                                    width,
                                    height,
                                    channels,
                                },
                                Packing {
                                    offsets,
                                    column,
                                    prime: prime.then_some(primes.as_slice()),
                                    mask,
                                    reverse,
                                    flip_x,
                                    flip_y,
                                    cap,
                                },
                                &mut probe,
                            );
                            let x = if flip_x { 'X' } else { 'x' };
                            let y = if flip_y { 'Y' } else { 'y' };
                            let order = if column {
                                format!("{y}{x}")
                            } else {
                                format!("{x}{y}")
                            };
                            let layout = format!(
                                "{lane}/mask-{mask:02x},{name},{},{order},{}",
                                if reverse { "msb" } else { "lsb" },
                                if prime { "prime" } else { "all" }
                            );
                            probe.inspect(&data, &layout);
                        }
                    }
                }
            }
        }
    }
    if !probe.found.is_empty() {
        let mut found = values
            .get("png.pixel_payloads")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for payload in probe.found {
            if !found.iter().any(|existing| {
                existing.get("kind") == payload.get("kind")
                    && existing.get("preview") == payload.get("preview")
            }) {
                found.push(payload);
            }
        }
        metrics.insert(metric!("png.pixel_payload_count"), found.len() as f64);
        values.insert_key(value_key!("png.pixel_payloads"), Value::Array(found));
    }
    metrics.insert(
        metric!("png.pixel_payload_count"),
        values
            .get("png.pixel_payloads")
            .and_then(Value::as_array)
            .map_or(0.0, |v| v.len() as f64),
    );
    metrics.insert(
        metric!("png.pixel_payload_probe_count"),
        metrics.get("png.pixel_payload_probe_count").unwrap_or(0.0) + probe.count as f64,
    );
    metrics.insert(
        metric!("png.pixel_payload_probe_bytes"),
        metrics.get("png.pixel_payload_probe_bytes").unwrap_or(0.0) + probe.bytes as f64,
    );
    metrics.insert(
        metric!("png.pixel_payload_probe_steps"),
        metrics.get("png.pixel_payload_probe_steps").unwrap_or(0.0) + probe.steps as f64,
    );
    metrics.insert(
        metric!("png.pixel_payload_limited"),
        metrics
            .get("png.pixel_payload_limited")
            .unwrap_or(0.0)
            .max(f64::from(u8::from(probe.limited))),
    );
    if probe.limited {
        let mut limits = Limits::default();
        limits.push(
            "pixel-payloads",
            "bounded pixel prefixes, traversal, or recovered-payload limit reached",
        );
        limits.emit(values, value_key!("png.limits"));
    }
}

#[cfg(test)]
mod tests;
