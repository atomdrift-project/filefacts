//! Shared analysis for media containers used as payload carriers.
//!
//! Fonts, images, audio and video files share a structure: a header, a
//! sequence of self-describing regions (chunks, boxes, tables, segments), and
//! a defined end. Every consumer reads only what that structure declares, so
//! any byte outside it is invisible — which is exactly what makes these
//! formats durable hiding places. A PNG with a payload past `IEND`, a WAV with
//! data past the `RIFF` length, an ICO whose directory leaves a hole: all three
//! render or play correctly and none of them is a font-specific problem.
//!
//! Rather than reimplement that reasoning per format, each container walker
//! reports which byte ranges its own structure accounts for, and this module
//! turns that into one shared `media.*` fact set:
//!
//! - `media.container` — `png`, `wav`, `gif`, `sfnt`, … which format claimed it
//! - `media.valid` — the structure parsed and fits inside the file
//! - `media.stowaway[]` — what the unaccounted-for bytes turn out to be
//! - `media.content_kind` — for a file with no valid container at all, what
//!   its bytes actually are
//! - `media.trailing_bytes` / `media.gap_bytes` / `media.stowaway_bytes` /
//!   `media.stowaway_entropy`
//!
//! One namespace means one set of rules covers every carrier, and a format
//! added later inherits the detections rather than needing its own copies.
//!
//! Deliberately *not* here: finding and decoding encoded content (base64
//! blobs, URLs, nested encodings). cleave already extracts strings from every
//! analysed file and runs a recursive decode pipeline that emits
//! `metadata/encoded-payload/*` and re-analyses the decoded bytes. Giving a
//! container a file type is what enrols it in that pipeline; duplicating the
//! decoding here would fork a mature capability for no gain.

use serde_json::Value as JsonValue;

use crate::metric;
use crate::output::{Metrics, Values};
use crate::scan::entropy;

/// Bytes of alignment padding tolerated between two adjacent regions before
/// the space between them counts as a hole. Chunked formats pad to 2- or
/// 4-byte boundaries; nothing legitimate leaves more.
const ALIGNMENT_SLACK: u64 = 3;

/// Unaccounted-for bytes below this are not treated as concealment.
///
/// Formats keep gaining chunk and box types, and a walker will always be a
/// little behind: PNG's `cICP` is a real, standardised chunk that was simply
/// missing from the known-types list, and leaving it unclaimed marked shipped
/// application icons invalid over 16 bytes. Nothing is hidden in 16 bytes, so
/// a floor here buys resilience to that drift at no detection cost — every
/// rule that consumes these facts sets its own threshold far above it.
const CONCEALMENT_FLOOR: u64 = 64;

/// A region the container's own structure accounts for.
pub(crate) struct Claim {
    pub(crate) start: u64,
    pub(crate) end: u64,
    /// True when the region legitimately holds free-form text or arbitrary
    /// author-supplied data (an ID3 comment, a PNG `tEXt`, an sfnt `name`).
    /// Such a region is still searched for executable and archive
    /// signatures, but its size is not counted as concealed and readable
    /// text in it is expected rather than reported.
    pub(crate) freeform: bool,
}

impl Claim {
    pub(crate) fn new(start: u64, end: u64) -> Self {
        Self {
            start,
            end,
            freeform: false,
        }
    }

    pub(crate) fn freeform(start: u64, end: u64) -> Self {
        Self {
            start,
            end,
            freeform: true,
        }
    }
}

/// What a container walker found: which format, whether it parsed, and the
/// byte ranges it accounts for.
pub(crate) struct Coverage {
    /// Format label, or `None` when no known container signature was present.
    pub(crate) container: Option<&'static str>,
    /// Byte offset where the structure begins (everything before it is header).
    pub(crate) header_end: u64,
    pub(crate) claims: Vec<Claim>,
    pub(crate) problems: Vec<String>,
    /// A total size the header declares, when the format carries one.
    pub(crate) declared_len: Option<u64>,
}

impl Coverage {
    pub(crate) fn new(container: &'static str, header_end: u64) -> Self {
        Self {
            container: Some(container),
            header_end,
            claims: Vec::new(),
            problems: Vec::new(),
            declared_len: None,
        }
    }

    /// No recognised container signature: the file is not what its name says.
    pub(crate) fn unrecognized() -> Self {
        Self {
            container: None,
            header_end: 0,
            claims: Vec::new(),
            problems: vec!["no container signature".to_string()],
            declared_len: None,
        }
    }

    pub(crate) fn claim(&mut self, start: u64, end: u64) {
        self.claims.push(Claim::new(start, end));
    }

    pub(crate) fn claim_freeform(&mut self, start: u64, end: u64) {
        self.claims.push(Claim::freeform(start, end));
    }

    pub(crate) fn problem(&mut self, what: impl Into<String>) {
        let what = what.into();
        if !self.problems.contains(&what) {
            self.problems.push(what);
        }
    }
}

/// Fold a walker's coverage into the shared `media.*` facts.
pub(crate) fn emit(bytes: &[u8], coverage: &Coverage, values: &mut Values, metrics: &mut Metrics) {
    let file_len = bytes.len() as u64;
    let mut stowaway: Vec<&'static str> = Vec::new();
    let mut stowaway_bytes: u64 = 0;
    let mut stowaway_entropy: f64 = 0.0;
    let mut problems = coverage.problems.clone();

    let mut note = |region: &[u8], counted: bool, allow_text: bool, out: &mut Vec<&'static str>| {
        if region.is_empty() {
            return;
        }
        if counted {
            stowaway_bytes = stowaway_bytes.saturating_add(region.len() as u64);
            stowaway_entropy = stowaway_entropy.max(entropy::shannon(region));
        }
        if let Some(kind) = classify_region(region) {
            let expected_text = !allow_text && matches!(kind, "text" | "base64" | "high_entropy");
            if !expected_text && !out.contains(&kind) {
                out.push(kind);
            }
        }
    };

    // Freeform regions are legitimately claimed content, so they are searched
    // for payload signatures but never counted as concealed bytes.
    for claim in &coverage.claims {
        if !claim.freeform {
            continue;
        }
        let (Ok(a), Ok(b)) = (usize::try_from(claim.start), usize::try_from(claim.end)) else {
            continue;
        };
        if let Some(region) = bytes.get(a..b.min(bytes.len())) {
            note(region, false, false, &mut stowaway);
        }
    }

    // Holes between claimed regions, and everything past the last one.
    // Freeform regions count as covering: an EXIF segment or a `tEXt` chunk is
    // part of the file even though its contents are author-supplied. They are
    // excluded from the overlap check instead, because a walker may report one
    // as a window *inside* a larger structural claim (a JPEG's APP1 sits
    // within the SOI..EOI span), and that nesting is not a malformed file.
    let mut extents: Vec<(u64, u64, bool)> = coverage
        .claims
        .iter()
        .filter_map(|c| (c.end > c.start).then_some((c.start, c.end, c.freeform)))
        .collect();
    extents.sort_unstable();

    let mut covered_to = coverage.header_end;
    let mut gap_bytes: u64 = 0;
    let mut overlapping = false;
    let mut structural_to = coverage.header_end;
    for &(start, end, freeform) in &extents {
        if !freeform {
            if start < structural_to {
                overlapping = true;
            }
            structural_to = structural_to.max(end);
        }
        if start < covered_to {
            // Already inside covered ground; nothing between it and the last
            // region to account for.
        } else if start - covered_to > ALIGNMENT_SLACK {
            let (Ok(a), Ok(b)) = (usize::try_from(covered_to), usize::try_from(start)) else {
                continue;
            };
            if let Some(region) = bytes.get(a..b.min(bytes.len())) {
                gap_bytes = gap_bytes.saturating_add(region.len() as u64);
                note(region, true, true, &mut stowaway);
            }
        }
        covered_to = covered_to.max(end);
    }

    // A header-declared length the file overruns hides bytes just as
    // effectively as running past the last chunk: the decoder stops early.
    let logical_end = coverage
        .declared_len
        .map_or(covered_to, |d| covered_to.max(d));
    let mut trailing_bytes = file_len.saturating_sub(logical_end);
    if coverage.container.is_some() && trailing_bytes > CONCEALMENT_FLOOR {
        trailing_bytes -= ALIGNMENT_SLACK;
        let (Ok(a), Ok(b)) = (usize::try_from(logical_end), usize::try_from(file_len)) else {
            return;
        };
        if let Some(region) = bytes.get(a..b.min(bytes.len())) {
            note(region, true, true, &mut stowaway);
        }
        problems.push("data appended after end of container".to_string());
    } else {
        trailing_bytes = 0;
    }

    if gap_bytes > CONCEALMENT_FLOOR {
        problems.push("bytes not claimed by the container".to_string());
    }
    if overlapping {
        problems.push("container regions overlap".to_string());
    }

    let valid = coverage.container.is_some() && problems.is_empty();
    if let Some(label) = coverage.container {
        values.insert("media.container", JsonValue::String(label.to_string()));
    } else {
        // Nothing here is the format the name claims. Say what it is instead:
        // this is the residue case, reached when the bytes carry no magic of
        // their own so no other analyzer claimed them.
        let kind = classify_region(bytes).unwrap_or("unknown");
        values.insert("media.content_kind", JsonValue::String(kind.to_string()));
    }
    values.insert("media.valid", JsonValue::Bool(valid));
    if !stowaway.is_empty() {
        values.insert(
            "media.stowaway",
            JsonValue::Array(
                stowaway
                    .iter()
                    .map(|s| JsonValue::String((*s).to_string()))
                    .collect(),
            ),
        );
    }
    if !problems.is_empty() {
        values.insert(
            "media.problems",
            JsonValue::Array(problems.into_iter().map(JsonValue::String).collect()),
        );
    }
    metrics.insert(metric!("media.trailing_bytes"), trailing_bytes as f64);
    metrics.insert(metric!("media.gap_bytes"), gap_bytes as f64);
    metrics.insert(metric!("media.stowaway_bytes"), stowaway_bytes as f64);
    metrics.insert(metric!("media.stowaway_entropy"), stowaway_entropy);
}

/// Identify what a run of bytes is, for regions a container does not account
/// for. Returns the most specific label that fits, or `None` for bytes with no
/// recognisable structure.
///
/// Signatures are matched anywhere in the region, not only at its start: a
/// payload is written at whatever offset the appender happened to be at, and
/// an author who knows the first bytes are checked will simply add a few. Each
/// check is anchored enough not to fire on compressed pixel or sample data —
/// `MZ` alone is two bytes and appears constantly in binary noise, so the DOS
/// header must also resolve to a real `PE\0\0`, exactly as a loader does.
pub(crate) fn classify_region(region: &[u8]) -> Option<&'static str> {
    if region.len() < 4 {
        return None;
    }
    if find_pe(region) {
        return Some("pe");
    }
    // bzip2's `BZh` is three bytes and occurs freely in base64 text (it read a
    // base64 blob as a bzip2 stream). Require the full stream header: `BZh`,
    // the block-size digit, and the compressed-block magic.
    if find_bzip2(region) {
        return Some("bzip2");
    }
    // `#!/` is likewise short. A shebang only means anything at the start of a
    // line, which is also the only place an interpreter honours it.
    if starts_line_with(region, b"#!/") {
        return Some("shebang");
    }
    for (magic, label) in [
        (&b"\x7fELF"[..], "elf"),
        (&b"\xcf\xfa\xed\xfe"[..], "macho"),
        (&b"\xce\xfa\xed\xfe"[..], "macho"),
        (&b"\xca\xfe\xba\xbe"[..], "macho"),
        (&b"PK\x03\x04"[..], "zip"),
        (&b"\x1f\x8b\x08"[..], "gzip"),
        (&b"\xfd7zXZ\x00"[..], "xz"),
        (&b"7z\xbc\xaf\x27\x1c"[..], "sevenz"),
        (&b"Rar!\x1a\x07"[..], "rar"),
        (&b"MSCF"[..], "cab"),
        (&b"\x28\xb5\x2f\xfd"[..], "zstd"),
    ] {
        if memchr::memmem::find(region, magic).is_some() {
            return Some(label);
        }
    }
    // No signature: fall back to what the byte distribution says. A container
    // never parks readable text or a compressed blob outside its structure.
    if printable_ratio(region) > 0.90 {
        return Some(if looks_base64(region) {
            "base64"
        } else {
            "text"
        });
    }
    if region.len() >= 512 && entropy::shannon(region) > 7.2 {
        return Some("high_entropy");
    }
    None
}

/// A DOS header whose `e_lfanew` resolves to the `PE\0\0` signature. This is
/// the same two-step a Windows loader performs, and it is what separates a
/// real embedded image from the `MZ` byte pair occurring in media data.
fn find_pe(region: &[u8]) -> bool {
    let mut from = 0usize;
    while let Some(rel) = memchr::memmem::find(&region[from..], b"MZ") {
        let mz = from + rel;
        if let Some(field) = region.get(mz + 0x3c..mz + 0x40) {
            let off = u32::from_le_bytes([field[0], field[1], field[2], field[3]]) as usize;
            if let Some(sig) = mz.checked_add(off).and_then(|at| region.get(at..at + 4))
                && sig == b"PE\0\0"
            {
                return true;
            }
        }
        from = mz + 2;
        if from >= region.len() {
            break;
        }
    }
    false
}

/// A complete bzip2 stream header: `BZh` + block size 1-9 + the
/// `1AY&SY` compressed-block magic that follows it.
fn find_bzip2(region: &[u8]) -> bool {
    let mut from = 0usize;
    while let Some(rel) = memchr::memmem::find(&region[from..], b"BZh") {
        let at = from + rel;
        if let Some(rest) = region.get(at + 3..at + 10)
            && rest[0].is_ascii_digit()
            && rest[0] != b'0'
            && &rest[1..7] == b"\x31\x41\x59\x26\x53\x59"
        {
            return true;
        }
        from = at + 3;
        if from >= region.len() {
            break;
        }
    }
    false
}

/// True when `needle` sits at the very start of `region` or immediately after
/// a newline — the only positions where a shebang is meaningful.
fn starts_line_with(region: &[u8], needle: &[u8]) -> bool {
    if region.starts_with(needle) {
        return true;
    }
    let mut from = 0usize;
    while let Some(rel) = memchr::memmem::find(&region[from..], needle) {
        let at = from + rel;
        if at > 0 && matches!(region[at - 1], b'\n' | b'\r') {
            return true;
        }
        from = at + 1;
        if from >= region.len() {
            break;
        }
    }
    false
}

/// Base64 rather than prose: a long run drawn only from the base64 alphabet.
fn looks_base64(region: &[u8]) -> bool {
    let sample = &region[..region.len().min(4096)];
    let coded = sample
        .iter()
        .filter(|&&b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'\n' | b'\r'))
        .count();
    sample.len() >= 64 && coded * 100 / sample.len() >= 98
}

/// Fraction of bytes that are printable ASCII or ordinary whitespace.
/// Near 1.0 means the region is text.
pub(crate) fn printable_ratio(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let n = bytes
        .iter()
        .filter(|&&b| (0x20..0x7f).contains(&b) || matches!(b, b'\t' | b'\n' | b'\r'))
        .count();
    n as f64 / bytes.len() as f64
}

/// Leading ASCII whitespace. A container begins with its signature; a payload
/// padded off the left margin to defeat a reviewer — or a size-limited content
/// sniffer — begins with hundreds of spaces.
pub(crate) fn leading_whitespace(bytes: &[u8]) -> usize {
    bytes.iter().take_while(|b| b.is_ascii_whitespace()).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(coverage: &Coverage, bytes: &[u8]) -> (Values, Metrics) {
        let mut v = Values::new();
        let mut m = Metrics::new();
        emit(bytes, coverage, &mut v, &mut m);
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
        out.extend(std::iter::repeat_n(0x41u8, body));
        out
    }

    #[test]
    fn fully_claimed_container_is_valid_and_quiet() {
        let bytes = vec![0u8; 512];
        let mut c = Coverage::new("test", 8);
        c.claim(8, 512);
        let (v, m) = run(&c, &bytes);
        assert_eq!(v.get("media.valid").and_then(|x| x.as_bool()), Some(true));
        assert!(stow(&v).is_empty());
        assert_eq!(m.get("media.trailing_bytes"), Some(0.0));
        assert_eq!(m.get("media.gap_bytes"), Some(0.0));
        assert_eq!(m.get("media.stowaway_bytes"), Some(0.0));
    }

    #[test]
    fn appended_executable_is_named() {
        let mut bytes = vec![0u8; 256];
        bytes.extend_from_slice(&fake_pe(2048));
        let mut c = Coverage::new("test", 8);
        c.claim(8, 256);
        let (v, m) = run(&c, &bytes);
        assert_eq!(stow(&v), vec!["pe"]);
        assert!(m.get("media.trailing_bytes").unwrap() > 2000.0);
        assert_eq!(v.get("media.valid").and_then(|x| x.as_bool()), Some(false));
    }

    #[test]
    fn interior_hole_is_measured_and_classified() {
        let mut bytes = vec![0u8; 128];
        bytes.extend_from_slice(b"PK\x03\x04payload riding in the hole");
        bytes.resize(1024, 0);
        let mut c = Coverage::new("test", 8);
        c.claim(8, 128);
        c.claim(600, 1024);
        let (v, m) = run(&c, &bytes);
        assert!(stow(&v).contains(&"zip".to_string()));
        assert!(m.get("media.gap_bytes").unwrap() > 400.0);
    }

    /// A freeform region (an ID3 comment, a PNG `tEXt`) legitimately holds
    /// text, so text there is not concealment and its size is not concealed
    /// space — but an executable signature in it still is.
    #[test]
    fn freeform_region_allows_text_but_not_executables() {
        let mut bytes = vec![0u8; 64];
        bytes.extend_from_slice(b"Copyright 2026 Example. All rights reserved. Comment field.");
        bytes.resize(512, 0);
        let mut c = Coverage::new("test", 8);
        c.claim(8, 64);
        c.claim_freeform(64, 200);
        c.claim(200, 512);
        let (v, m) = run(&c, &bytes);
        assert!(stow(&v).is_empty());
        assert_eq!(m.get("media.stowaway_bytes"), Some(0.0));

        let mut bytes = vec![0u8; 64];
        bytes.extend_from_slice(&fake_pe(64));
        bytes.resize(512, 0);
        let mut c = Coverage::new("test", 8);
        c.claim(8, 64);
        c.claim_freeform(64, 300);
        c.claim(300, 512);
        let (v, _) = run(&c, &bytes);
        assert_eq!(stow(&v), vec!["pe"]);
    }

    #[test]
    fn unrecognized_container_reports_content_kind() {
        let mut blob = Vec::new();
        let mut x: u32 = 0x1234_5678;
        while blob.len() < 4096 {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            blob.extend_from_slice(&x.to_le_bytes());
        }
        let (v, _) = run(&Coverage::unrecognized(), &blob);
        assert_eq!(
            v.get("media.content_kind").and_then(|x| x.as_str()),
            Some("high_entropy")
        );
        assert_eq!(v.get("media.valid").and_then(|x| x.as_bool()), Some(false));
    }

    #[test]
    fn mz_without_pe_signature_is_not_an_executable() {
        let mut bytes = vec![0u8; 64];
        let mut noise = vec![0u8; 2048];
        noise[100] = b'M';
        noise[101] = b'Z';
        bytes.extend_from_slice(&noise);
        let mut c = Coverage::new("test", 8);
        c.claim(8, 64);
        let (v, _) = run(&c, &bytes);
        assert!(!stow(&v).contains(&"pe".to_string()));
    }

    #[test]
    fn declared_length_shorter_than_file_hides_the_remainder() {
        let mut bytes = vec![0u8; 256];
        bytes.extend_from_slice(&fake_pe(1024));
        let mut c = Coverage::new("test", 8);
        c.claim(8, 256);
        c.declared_len = Some(256);
        let (v, m) = run(&c, &bytes);
        assert_eq!(stow(&v), vec!["pe"]);
        assert!(m.get("media.trailing_bytes").unwrap() > 1000.0);
    }

    #[test]
    fn alignment_padding_is_not_a_hole() {
        let bytes = vec![0u8; 512];
        let mut c = Coverage::new("test", 8);
        c.claim(8, 100);
        c.claim(102, 512); // two bytes of pad-to-even between regions
        let (_, m) = run(&c, &bytes);
        assert_eq!(m.get("media.gap_bytes"), Some(0.0));
    }
}
