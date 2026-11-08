//! Whole executables carried inside another file: PE and ELF images, raw or
//! base64-encoded, found by strict header validation.
//!
//! Droppers, reflective loaders, self-extracting installers and multi-stage
//! payloads all carry a second program. Each validated image becomes one
//! `binary.embedded[]` entry -- its offset in the host, kind, variant,
//! physical size, and any encoding or installer format -- and
//! `binary.embedded_binaries` counts them. A consumer that analyzes the
//! payloads carves them from there (decoding base64 first).
//!
//! Validation is strict so a stray `MZ` or `\x7fELF` is not a program: a PE
//! needs a plausible `e_lfanew`, signature, machine, section table inside the
//! file and optional-header magic; an ELF needs a consistent identity,
//! header sizes, tables inside the file and a loadable segment.

use std::collections::HashSet;

use memchr::memmem;
use serde_json::{Map, Value as JsonValue};
use sha2::{Digest, Sha256};

use crate::bytes::{u16_le, u32_be, u32_le, u64_be, u64_le};
use crate::metric;
use crate::output::{Metrics, Values};
use crate::value_key;

/// Images reported per file (prevents noise on heavily packed files).
const MAX_EMBEDDED: usize = 20;

/// Candidate validation is spread across the file so a dense prefix cannot
/// starve a later stage. Per-region quotas cap header checks at 8,192 and
/// valid candidates at 1,024 per encoding/kind scan while the magic-byte walk
/// stays linear and allocation-free.
const CANDIDATE_BUCKETS: usize = 256;
const CANDIDATES_PER_BUCKET: u8 = 4;
const HEADER_CHECKS_PER_BUCKET: u8 = 32;

/// Minimum credible embedded PE size in bytes.
const MIN_BINARY_SIZE: usize = 512;
/// Tiny packer stubs often mimic ELF headers without carrying a real payload.
const MIN_EMBEDDED_ELF_SIZE: usize = 8 * 1024;

/// Minimum base64-run length considered a packed-binary candidate. Smaller
/// blobs decode below [`MIN_EMBEDDED_ELF_SIZE`]; this gate just avoids
/// decoding every small base64 string in a data section.
const MIN_BASE64_RUN: usize = 8 * 1024;
/// Base64 of an aligned `\x7fELF` prefix.
const ELF_BASE64_PREFIX: &[u8] = b"f0VMRg";
/// Base64 of the universal DOS header start `MZ\x90\x00`.
const PE_BASE64_PREFIX: &[u8] = b"TVqQAA";

/// Kind of an embedded image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EmbeddedKind {
    Pe32,
    Pe64,
    Elf32Le,
    Elf32Be,
    Elf64Le,
    Elf64Be,
}

impl EmbeddedKind {
    /// The program family: `pe` or `elf`.
    pub(crate) fn family(self) -> &'static str {
        match self {
            Self::Pe32 | Self::Pe64 => "pe",
            Self::Elf32Le | Self::Elf32Be | Self::Elf64Le | Self::Elf64Be => "elf",
        }
    }

    /// The exact layout.
    pub(crate) fn variant(self) -> &'static str {
        match self {
            Self::Pe32 => "pe32",
            Self::Pe64 => "pe64",
            Self::Elf32Le => "elf32le",
            Self::Elf32Be => "elf32be",
            Self::Elf64Le => "elf64le",
            Self::Elf64Be => "elf64be",
        }
    }
}

/// A validated image found within a larger file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EmbeddedBinary {
    /// Byte offset within the host. For a base64 payload, the start of the
    /// encoded run -- where the dropper physically sits.
    pub(crate) offset: usize,
    pub(crate) kind: EmbeddedKind,
    /// Physical size; for base64, the decoded payload's size.
    pub(crate) size: usize,
    /// `Some("base64")` when the payload must be decoded before use.
    pub(crate) encoding: Option<&'static str>,
    /// An installer format inferred from the bytes around the program
    /// (`nsis`, `inno`), which also sets how far the image extends.
    pub(crate) format: Option<&'static str>,
}

/// Emit `binary.embedded[]` and `binary.embedded_binaries` for `data`,
/// leaving out images that start inside `signature` -- a PE's own
/// certificate table, whose contents are signature data, not payloads --
/// and return the images emitted.
pub(crate) fn emit(
    data: &[u8],
    signature: Option<std::ops::Range<usize>>,
    values: &mut Values,
    metrics: &mut Metrics,
) -> Vec<EmbeddedBinary> {
    let mut found = scan(data);
    if let Some(signature) = signature {
        found.retain(|binary| !signature.contains(&binary.offset));
    }
    if found.is_empty() {
        return found;
    }
    metrics.insert(metric!("binary.embedded_binaries"), found.len() as f64);
    let entries = found
        .iter()
        .map(|binary| {
            let mut obj = Map::new();
            obj.insert("offset".into(), binary.offset.into());
            obj.insert("kind".into(), binary.kind.family().into());
            obj.insert("variant".into(), binary.kind.variant().into());
            obj.insert("size".into(), binary.size.into());
            if let Some(encoding) = binary.encoding {
                obj.insert("encoding".into(), encoding.into());
            }
            if let Some(format) = binary.format {
                obj.insert("format".into(), format.into());
            }
            JsonValue::Object(obj)
        })
        .collect();
    values.insert_key(value_key!("binary.embedded"), JsonValue::Array(entries));
    found
}

/// The embedded images of `data`: raw PE and ELF headers plus base64
/// payloads, sorted by offset, at most [`MAX_EMBEDDED`]. Candidate discovery
/// is wider than the budget: content-distinct images are kept first, then
/// remaining slots are filled with offset-stratified duplicates.
pub(crate) fn scan(data: &[u8]) -> Vec<EmbeddedBinary> {
    let mut results = Vec::new();
    scan_magic(data, b"MZ", 2, validate_pe, &mut results);
    scan_magic(data, b"\x7fELF", 4, validate_elf, &mut results);
    scan_base64(data, &mut results);
    results.sort_by_key(|e| e.offset);
    select(data, results)
}

/// Validate every `magic` occurrence past the host's own header (`skip`
/// bytes), within the per-region quotas.
fn scan_magic(
    data: &[u8],
    magic: &[u8],
    skip: usize,
    validate: fn(&[u8], usize) -> Option<EmbeddedBinary>,
    results: &mut Vec<EmbeddedBinary>,
) {
    let start = skip.min(data.len());
    let mut quotas = Quotas::default();
    for pos in memmem::find_iter(data.get(start..).unwrap_or_default(), magic) {
        let offset = pos.saturating_add(start);
        let Some(bucket) = quotas.admit(offset, data.len()) else {
            continue;
        };
        if let Some(found) = validate(data, offset) {
            results.push(found);
            quotas.retain(bucket);
        }
    }
}

/// Per-region admission: header checks and retained candidates per bucket.
struct Quotas {
    retained: [u8; CANDIDATE_BUCKETS],
    checked: [u8; CANDIDATE_BUCKETS],
}

impl Default for Quotas {
    fn default() -> Self {
        Self {
            retained: [0; CANDIDATE_BUCKETS],
            checked: [0; CANDIDATE_BUCKETS],
        }
    }
}

impl Quotas {
    /// The bucket of a candidate at `offset`, counted as checked, or `None`
    /// when its region is already full.
    fn admit(&mut self, offset: usize, len: usize) -> Option<usize> {
        let bucket = candidate_bucket(offset, len);
        let checked = self.checked.get_mut(bucket)?;
        let retained = self.retained.get(bucket)?;
        if *retained >= CANDIDATES_PER_BUCKET || *checked >= HEADER_CHECKS_PER_BUCKET {
            return None;
        }
        *checked += 1;
        Some(bucket)
    }

    fn retain(&mut self, bucket: usize) {
        if let Some(retained) = self.retained.get_mut(bucket) {
            *retained = retained.saturating_add(1);
        }
    }
}

fn candidate_bucket(offset: usize, len: usize) -> usize {
    let width = len.div_ceil(CANDIDATE_BUCKETS).max(1);
    (offset / width).min(CANDIDATE_BUCKETS - 1)
}

/// Keep at most [`MAX_EMBEDDED`] candidates without letting repeated content
/// consume every slot: distinct payloads first, sampled across the file.
fn select(data: &[u8], candidates: Vec<EmbeddedBinary>) -> Vec<EmbeddedBinary> {
    if candidates.len() <= MAX_EMBEDDED {
        return candidates;
    }
    let mut seen = HashSet::new();
    let (mut unique, mut duplicates) = (Vec::new(), Vec::new());
    for candidate in candidates {
        if seen.insert(fingerprint(data, &candidate)) {
            unique.push(candidate);
        } else {
            duplicates.push(candidate);
        }
    }
    let mut selected = take_stratified(unique, MAX_EMBEDDED);
    let remaining = MAX_EMBEDDED.saturating_sub(selected.len());
    selected.extend(take_stratified(duplicates, remaining));
    selected.sort_by_key(|e| e.offset);
    selected
}

/// SHA-256 over a bounded, position-independent view of a candidate: small
/// payloads in full, large ones as head/middle/tail windows so overlapping
/// multi-hundred-megabyte images cannot amplify the cost.
fn fingerprint(data: &[u8], candidate: &EmbeddedBinary) -> [u8; 32] {
    const WINDOW: usize = 8 * 1024;
    let mut hasher = Sha256::new();
    hasher.update(candidate.kind.family().as_bytes());
    hasher.update(candidate.encoding.unwrap_or("raw").as_bytes());
    hasher.update(candidate.size.to_le_bytes());
    let encoded = if candidate.encoding == Some("base64") {
        candidate.size.saturating_mul(4).div_ceil(3)
    } else {
        candidate.size
    };
    let available = data.get(candidate.offset..).unwrap_or_default();
    let bytes = available.get(..encoded).unwrap_or(available);
    if bytes.len() <= WINDOW * 3 {
        hasher.update(bytes);
    } else {
        let middle = bytes.len() / 2;
        for window in [
            bytes.get(..WINDOW),
            bytes.get(middle - WINDOW / 2..middle + WINDOW / 2),
            bytes.get(bytes.len() - WINDOW..),
        ]
        .into_iter()
        .flatten()
        {
            hasher.update(window);
        }
    }
    hasher.finalize().into()
}

/// Deterministically keep the first and last items and spread the rest of
/// the picks across the ordered input.
fn take_stratified(items: Vec<EmbeddedBinary>, limit: usize) -> Vec<EmbeddedBinary> {
    if items.len() <= limit {
        return items;
    }
    if limit <= 1 {
        return items.into_iter().take(limit).collect();
    }
    let last = items.len() - 1;
    (0..limit)
        .filter_map(|slot| items.get(slot * last / (limit - 1)).cloned())
        .collect()
}

// ── Base64-encoded payloads ─────────────────────────────────────────────────

fn scan_base64(data: &[u8], results: &mut Vec<EmbeddedBinary>) {
    for (prefix, family) in [(ELF_BASE64_PREFIX, "elf"), (PE_BASE64_PREFIX, "pe")] {
        let mut quotas = Quotas::default();
        for start in memmem::find_iter(data, prefix) {
            let Some(bucket) = quotas.admit(start, data.len()) else {
                continue;
            };
            let run = data.get(start..).unwrap_or_default();
            let run_len = run
                .iter()
                .take_while(|&&b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
                .count();
            if run_len < MIN_BASE64_RUN {
                continue;
            }
            // Decode just enough to confirm the magic: 256 chars, 192 bytes.
            let head = run.get(..256).unwrap_or_default();
            let Ok(decoded) =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, head)
            else {
                continue;
            };
            // The kind decoded must be the one the marker claimed, or the
            // marker was a coincidence.
            let Some(kind) = classify_decoded_head(&decoded).filter(|k| k.family() == family)
            else {
                continue;
            };
            let size = (run_len / 4) * 3;
            if size < MIN_EMBEDDED_ELF_SIZE {
                continue;
            }
            results.push(EmbeddedBinary {
                offset: start,
                kind,
                size,
                encoding: Some("base64"),
                format: None,
            });
            quotas.retain(bucket);
        }
    }
}

fn classify_decoded_head(head: &[u8]) -> Option<EmbeddedKind> {
    if head.len() < 8 {
        return None;
    }
    if head.starts_with(b"\x7fELF") {
        return Some(match (head.get(4)?, head.get(5)?) {
            (1, 1) => EmbeddedKind::Elf32Le,
            (1, 2) => EmbeddedKind::Elf32Be,
            (2, 1) => EmbeddedKind::Elf64Le,
            (2, 2) => EmbeddedKind::Elf64Be,
            _ => return None,
        });
    }
    // The decoded head does not reach the PE header (~256 bytes vs 0x80
    // minimum), so DOS magic is accepted alone; consumers re-validate.
    head.starts_with(b"MZ").then_some(EmbeddedKind::Pe64)
}

// ── PE ──────────────────────────────────────────────────────────────────────

/// A PE image at `offset`: MZ → `e_lfanew` → `PE\0\0` → machine → section
/// count → optional-header magic, with every section inside the file.
fn validate_pe(data: &[u8], offset: usize) -> Option<EmbeddedBinary> {
    const VALID_MACHINES: &[u16] = &[
        0x014C, // i386
        0x8664, // x86-64
        0x01C0, // ARM LE
        0x01C2, // ARM Thumb
        0x01C4, // ARM Thumb-2 / ARMv7
        0xAA64, // ARM64
        0x0200, // IA-64
        0x5032, // RISC-V 32
        0x5064, // RISC-V 64
        0x0166, // MIPS I
        0x0366, // MIPS FPU
        0x0466, // MIPS FPU16
    ];
    let at = |rel: usize| offset.checked_add(rel);
    let e_lfanew = usize::try_from(u32_le(data, at(0x3C)?)?).ok()?;
    if !(4..=1024).contains(&e_lfanew) || !e_lfanew.is_multiple_of(4) {
        return None;
    }
    let pe_base = at(e_lfanew)?;
    if data.get(pe_base..pe_base.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    if !VALID_MACHINES.contains(&u16_le(data, pe_base + 4)?) {
        return None;
    }
    let sections = usize::from(u16_le(data, pe_base + 6)?);
    if sections == 0 || sections > 96 {
        return None;
    }
    let optional_header_size = usize::from(u16_le(data, pe_base + 20)?);
    let kind = match u16_le(data, pe_base + 24)? {
        0x010B => EmbeddedKind::Pe32,
        0x020B => EmbeddedKind::Pe64,
        _ => return None,
    };
    let section_table = pe_base.checked_add(24 + optional_header_size)?;
    let section_table_end = section_table.checked_add(sections * 40)?;
    if section_table_end > data.len() {
        return None;
    }
    let available = data.len() - offset;
    let mut physical = section_table_end - offset;
    // Reject PE-like blobs whose sections point outside the embedded slice.
    for header in (0..sections).map(|i| section_table + i * 40) {
        let raw_size = usize::try_from(u32_le(data, header + 16)?).ok()?;
        let raw_pointer = usize::try_from(u32_le(data, header + 20)?).ok()?;
        if raw_size == 0 {
            continue;
        }
        let end = raw_pointer.checked_add(raw_size)?;
        if raw_pointer == 0 || end > available {
            return None;
        }
        physical = physical.max(end);
    }
    // Authenticode's security directory holds a file offset, not an RVA:
    // include it so a signed child is not carved into an unsigned fragment.
    let standard_fields = if kind == EmbeddedKind::Pe64 { 112 } else { 96 };
    let security_directory = pe_base + 24 + standard_fields + 4 * 8;
    if let (Some(cert_offset), Some(cert_size)) = (
        u32_le(data, security_directory).and_then(|v| usize::try_from(v).ok()),
        u32_le(data, security_directory + 4).and_then(|v| usize::try_from(v).ok()),
    ) && cert_offset > 0
        && cert_size > 0
        && let Some(end) = cert_offset.checked_add(cert_size)
        && end <= available
    {
        physical = physical.max(end);
    }
    let image = data.get(offset..)?;
    let format = installer_format(image);
    let installer_size = match format {
        Some("nsis") => nsis_physical_size(image),
        Some("inno") => Some(available),
        _ => None,
    };
    // SizeOfImage describes the mapped address space; on disk it would swallow
    // neighbouring resources into this child, so the physical span is used.
    let size = physical.max(installer_size.unwrap_or(0)).min(available);
    (size >= MIN_BINARY_SIZE).then_some(EmbeddedBinary {
        offset,
        kind,
        size,
        encoding: None,
        format,
    })
}

/// The installer a PE stub belongs to, from the bytes after its header.
fn installer_format(image: &[u8]) -> Option<&'static str> {
    if memmem::find(image, &[0xEF, 0xBE, 0xAD, 0xDE]).is_some()
        && [
            b"Nullsoft Install System".as_slice(),
            b"NSIS Error",
            b"nsis.sf.net/NSIS_Error",
            b"/NCRC",
        ]
        .iter()
        .any(|marker| memmem::find(image, marker).is_some())
    {
        return Some("nsis");
    }
    // The setup-data marker must sit near the stub: an unbounded search also
    // matches a host installer's data far beyond an unrelated interior PE,
    // and the `inno` size (to end of file) then swallowed the rest of the
    // host -- a helper DLL in a 190 MB installer was analyzed as a 189 MB
    // binary. A real stub's data follows within ~100 KB; 1 MiB is generous.
    const INNO_MARKER_WINDOW: usize = 1 << 20;
    let window = image.get(..INNO_MARKER_WINDOW).unwrap_or(image);
    memmem::find(window, b"Inno Setup Setup Data")
        .is_some()
        .then_some("inno")
}

/// An NSIS installer's extent: its first header plus archive size, plus
/// the three-byte tail 7-Zip reports separately.
fn nsis_physical_size(image: &[u8]) -> Option<usize> {
    let header = memmem::find_iter(image, &[0xEF, 0xBE, 0xAD, 0xDE]).find(|&pos| {
        image.get(pos.saturating_add(4)..pos.saturating_add(16)) == Some(b"NullsoftInst".as_slice())
    })?;
    let archive_size = usize::try_from(u32_le(image, header.checked_add(20)?)?).ok()?;
    let end = header.checked_add(archive_size)?.checked_add(3)?;
    (end <= image.len()).then_some(end)
}

// ── ELF ─────────────────────────────────────────────────────────────────────

/// ELF `e_machine` values accepted.
const VALID_ELF_MACHINES: &[u16] = &[
    0x0002, // SPARC
    0x0003, // x86
    0x0008, // MIPS
    0x0014, // PowerPC
    0x0015, // PowerPC 64
    0x0028, // ARM
    0x002A, // SuperH
    0x0032, // IA-64
    0x003E, // x86-64
    0x00B7, // AArch64
    0x00F3, // RISC-V
    0x00F7, // BPF
    0x016F, // s390x
];

/// An ELF image at `offset`: a consistent identity, the class's header and
/// table entry sizes, tables inside the file and a non-empty loadable
/// segment.
fn validate_elf(data: &[u8], offset: usize) -> Option<EmbeddedBinary> {
    let image = data.get(offset..)?;
    let class = *image.get(4)?;
    let encoding = *image.get(5)?;
    if !matches!(class, 1 | 2) || !matches!(encoding, 1 | 2) || *image.get(6)? != 1 {
        return None;
    }
    let le = encoding == 1;
    let r16 = |at: usize| -> Option<usize> {
        let bytes = image.get(at..at.checked_add(2)?)?;
        let raw = [*bytes.first()?, *bytes.get(1)?];
        Some(usize::from(if le {
            u16::from_le_bytes(raw)
        } else {
            u16::from_be_bytes(raw)
        }))
    };
    let r32 = |at: usize| -> Option<usize> {
        let v = if le {
            u32_le(image, at)
        } else {
            u32_be(image, at)
        }?;
        usize::try_from(v).ok()
    };
    let r64 = |at: usize| -> Option<usize> {
        let v = if le {
            u64_le(image, at)
        } else {
            u64_be(image, at)
        }?;
        usize::try_from(v).ok()
    };
    let word = |at: usize| if class == 1 { r32(at) } else { r64(at) };

    let e_type = r16(16)?;
    if e_type == 0
        || e_type > 4
        || r32(20)? != 1
        || !VALID_ELF_MACHINES.contains(&u16::try_from(r16(18)?).ok()?)
    {
        return None;
    }
    let (kind, header_size, ph_size, sh_size) = match (class, le) {
        (1, true) => (EmbeddedKind::Elf32Le, 52, 32, 40),
        (1, false) => (EmbeddedKind::Elf32Be, 52, 32, 40),
        (_, true) => (EmbeddedKind::Elf64Le, 64, 56, 64),
        (_, false) => (EmbeddedKind::Elf64Be, 64, 56, 64),
    };
    let (phoff_at, shoff_at, ehsize_at) = if class == 1 {
        (28, 32, 40)
    } else {
        (32, 40, 52)
    };
    if r16(ehsize_at)? != header_size {
        return None;
    }
    let phoff = word(phoff_at)?;
    let shoff = word(shoff_at)?;
    let phentsize = r16(ehsize_at + 2)?;
    let phnum = r16(ehsize_at + 4)?;
    let shentsize = r16(ehsize_at + 6)?;
    let shnum = r16(ehsize_at + 8)?;
    let shstrndx = r16(ehsize_at + 10)?;
    if (phnum == 0 && shnum == 0)
        || phnum > 256
        || shnum > 512
        || (phnum > 0 && phentsize != ph_size)
        || (shnum > 0 && shentsize != sh_size)
        || (phnum == 0 && phoff != 0)
        || (shnum == 0 && (shoff != 0 || shstrndx != 0))
        || (shnum > 0 && shstrndx >= shnum && shstrndx != 0xFFFF)
    {
        return None;
    }
    let available = image.len();
    let table_end = |table: usize, count: usize, entry: usize| -> Option<usize> {
        if count == 0 {
            return Some(0);
        }
        if table < header_size || table >= available {
            return None;
        }
        let end = table.checked_add(count.checked_mul(entry)?)?;
        (end <= available).then_some(end)
    };
    let mut size = header_size
        .max(table_end(phoff, phnum, phentsize)?)
        .max(table_end(shoff, shnum, shentsize)?);
    let mut loadable = 0usize;
    for header in (0..phnum).map(|i| phoff + i * phentsize) {
        if r32(header)? != 1 {
            continue;
        }
        let (p_offset, p_filesz) = if class == 1 {
            (r32(header + 4)?, r32(header + 16)?)
        } else {
            (r64(header + 8)?, r64(header + 32)?)
        };
        let end = p_offset.checked_add(p_filesz)?;
        if p_filesz == 0 || end > available {
            return None;
        }
        loadable += 1;
        size = size.max(end);
    }
    if phnum > 0 && loadable == 0 {
        return None;
    }
    (MIN_EMBEDDED_ELF_SIZE..=available)
        .contains(&size)
        .then_some(EmbeddedBinary {
            offset,
            kind,
            size,
            encoding: None,
            format: None,
        })
}

#[cfg(test)]
mod tests;
