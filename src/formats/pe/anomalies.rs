//! Header arithmetic that does not add up: section extents past the file,
//! misalignment and overlap, an entry point outside the code, overlays, a
//! rewritten DOS stub, a stale checksum, malformed data directories, and a
//! container reshaped around an unchanged program (inflated headers, data
//! directories in sections named for others, sections stuffed with prose).

use goblin::pe::PE;
use goblin::pe::section_table::{IMAGE_SCN_MEM_WRITE, SectionTable};
use serde_json::Value as JsonValue;

use super::layout::{self, CERTIFICATE_DIRECTORY, DIRECTORY_NAMES};
use crate::bytes::{sat_usize, u16_le, u32_le};
use crate::formats::common::put_str;
use crate::metric;
use crate::output::{Metrics, Section, Values};
use crate::value_key;

/// Container geometry: the shape of the file around the program.
///
/// A PE can be restructured — padded, renamed, stuffed — without one
/// instruction changing, and every behavioural signal keeps describing the
/// original program. A genuine signed utility can be given a 10 MB
/// `SizeOfHeaders` (a zero hole the loader maps) and sections stuffed with
/// licence prose; only the container's shape gives it away.
///
/// - `pe.headers_size` / `pe.headers_size_ratio` — `SizeOfHeaders`, and its
///   share of the file. Nothing bounds it above, and even a 96-section image
///   needs under 8 KB, so a large value is a deliberate choice.
/// - `pe.prose_section_count` / `pe.executable_prose_section_count` —
///   sections whose bytes are natural-language text, overall and among those
///   mapped executable: text in a CODE|EXECUTE page is not a misfiled
///   resource, it is a section whose declared purpose its contents cannot
///   serve.
pub(super) fn container_geometry(
    size_of_headers: Option<u32>,
    bytes: &[u8],
    sections: &[Section],
    metrics: &mut Metrics,
) {
    if let Some(headers) = size_of_headers.map(f64::from) {
        metrics.insert(metric!("pe.headers_size"), headers);
        if !bytes.is_empty() {
            metrics.insert(
                metric!("pe.headers_size_ratio"),
                headers / bytes.len() as f64,
            );
        }
    }
    let (mut prose, mut prose_executable) = (0_u32, 0_u32);
    for section in sections {
        let Some(data) = bytes
            .get(sat_usize(section.file_offset)..)
            .and_then(|rest| rest.get(..sat_usize(section.file_size)))
        else {
            continue;
        };
        if section_is_prose(data) {
            prose = prose.saturating_add(1);
            if section.is_executable() {
                prose_executable = prose_executable.saturating_add(1);
            }
        }
    }
    metrics.insert(metric!("pe.prose_section_count"), f64::from(prose));
    metrics.insert(
        metric!("pe.executable_prose_section_count"),
        f64::from(prose_executable),
    );
}

/// Whether a section's bytes are natural-language prose rather than code or
/// structured data.
///
/// Trailing zero padding to `FileAlignment` is trimmed first — it is layout,
/// not content — and a section too short to judge is not prose. Prose runs
/// ~0.99 printable, ~0.15 spaces and ~0.80 letters, while compiled code and
/// structured tables sit below 0.67, 0.02 and 0.46; the thresholds are set in
/// the empty middle.
fn section_is_prose(bytes: &[u8]) -> bool {
    let trimmed = bytes
        .iter()
        .rposition(|&b| b != 0)
        .and_then(|last| bytes.get(..=last))
        .unwrap_or_default();
    // Below this a run of ASCII is as likely to be a string-table fragment as
    // a document, and the ratios get noisy.
    if trimmed.len() < 256 {
        return false;
    }
    let (mut printable, mut spaces, mut letters) = (0_usize, 0_usize, 0_usize);
    for &b in trimmed {
        printable += usize::from((0x20..0x7f).contains(&b) || matches!(b, b'\t' | b'\n' | b'\r'));
        spaces += usize::from(b == b' ');
        letters += usize::from(b.is_ascii_alphabetic());
    }
    let len = trimmed.len() as f64;
    printable as f64 / len >= 0.95 && spaces as f64 / len >= 0.08 && letters as f64 / len >= 0.60
}

/// The data directory a standard section name is *reserved for*. Only names
/// with a rigid, single-purpose convention are listed: `.text`, `.rdata` and
/// `.data` are absent because real toolchains park imports, TLS, debug and
/// load-config data in all three, and a packer's invented name (`UPX1`,
/// `.vmp0`) claims nothing. That keeps `pe.directory_section_mismatch_count`
/// a lie detector rather than a novelty detector.
fn section_name_reserved_for(name: &str) -> Option<&'static str> {
    match name {
        ".rsrc" => Some("resource"),
        ".reloc" => Some("base_relocation"),
        ".edata" => Some("export"),
        ".idata" => Some("import"),
        ".pdata" => Some("exception"),
        ".tls" => Some("tls"),
        ".didat" => Some("delay_import"),
        _ => None,
    }
}

/// Section extents past the end of the file, from binform's reading of the
/// section table when goblin could not parse the image. Only a complete,
/// bounded table counts: one holding fewer than the COFF header's `count`
/// sections says nothing about how many overflow.
pub(super) fn partial_section_overflows(
    sections: &[SectionTable],
    count: u16,
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
) {
    let count = usize::from(count);
    if count == 0 || count > layout::MAX_SECTIONS || sections.len() != count {
        tracing::debug!(
            target: "filefacts::pe",
            format = "pe",
            stage = "section-table",
            declared = count,
            read = sections.len(),
            "section table incomplete or unbounded; overflow count not reported"
        );
        return;
    }
    let names: Vec<JsonValue> = sections
        .iter()
        .filter(|s| {
            s.size_of_raw_data != 0
                && u64::from(s.pointer_to_raw_data) + u64::from(s.size_of_raw_data)
                    > bytes.len() as u64
        })
        .map(|s| JsonValue::String(s.real_name.clone().unwrap_or_default()))
        .collect();
    metrics.insert(metric!("pe.section_overflow_count"), names.len() as f64);
    if !names.is_empty() {
        values.insert_key(
            value_key!("pe.overflowing_sections"),
            JsonValue::Array(names),
        );
    }
}

/// Sections whose `VirtualSize` is more than four times their
/// `SizeOfRawData` — the packer fingerprint, since the runtime decompresses
/// payload bytes into a much larger memory image.
pub(super) fn inflated_sections(pe: &PE<'_>, values: &mut Values) {
    let names: Vec<JsonValue> = pe
        .sections
        .iter()
        .filter_map(|s| {
            let vsize = u64::from(s.virtual_size);
            let rsize = u64::from(s.size_of_raw_data);
            if rsize == 0 || vsize <= rsize.saturating_mul(4) {
                return None;
            }
            s.name().ok().map(|n| JsonValue::String(n.to_string()))
        })
        .collect();
    if !names.is_empty() {
        values.insert_key(value_key!("pe.inflated_sections"), JsonValue::Array(names));
    }
}

/// Classify the entry-point RVA against the section table and emit
/// overlay bounds (file bytes beyond the last on-disk section, with
/// the Certificate Table excluded so signed binaries don't look like
/// they all have giant overlays).
///
/// Emits to metrics:
/// - `pe.entry_in_header`     — EP RVA lands inside the SizeOfHeaders region.
/// - `pe.entry_in_writable_section` — EP's section has IMAGE_SCN_MEM_WRITE.
/// - `pe.entry_outside_sections`    — EP non-zero, not in any section,
///   and the file is an EXE (not a DLL/driver where EP=0 is normal).
/// - `pe.has_overlay`, `pe.overlay_offset`, `pe.overlay_size`,
///   `pe.overlay_end` — overlay extent in file-offset space (the
///   Authenticode table at the end of the file is not overlay).
///
/// Emits to values:
/// - `pe.entry_section` — name of the section containing the EP RVA.
/// - `binary.overlay_archive` — the archive the overlay starts with.
pub(super) fn entry_and_overlay(
    pe: &PE<'_>,
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
) {
    let Some(opt) = pe.header.optional_header.as_ref() else {
        return;
    };
    let ep_rva = u64::from(opt.standard_fields.address_of_entry_point);
    let size_of_headers = u64::from(opt.windows_fields.size_of_headers);

    if size_of_headers != 0 && ep_rva != 0 && ep_rva < size_of_headers {
        metrics.insert(metric!("pe.entry_in_header"), 1.0);
    }

    let entry_section = layout::section_containing(&pe.sections, ep_rva);
    if let Some(section) = entry_section {
        if section.characteristics & IMAGE_SCN_MEM_WRITE != 0 {
            metrics.insert(metric!("pe.entry_in_writable_section"), 1.0);
        }
        if let Ok(name) = section.name() {
            // Entry belongs in a code section (`.text`, `CODE`). Resolving
            // into a section outside the toolchain set is the redirection
            // tell of a section-append infector — the PE analogue of ELF's
            // note-cavity entry redirection. Packers also relocate the entry
            // into their own section, so this is corroboration rather than a
            // standalone verdict.
            if !crate::is_well_known_section_name(name) {
                metrics.insert(metric!("pe.entry_in_nonstandard_section"), 1.0);
            }
            put_str(values, value_key!("pe.entry_section"), name);
        }
    }
    // EP=0 on a DLL or driver is normal; only flag "outside sections"
    // when the file is structurally an EXE with a non-zero EP.
    if entry_section.is_none() && ep_rva != 0 && !pe.is_lib {
        metrics.insert(metric!("pe.entry_outside_sections"), 1.0);
    }

    // Overlay = file bytes past the last on-disk section extent, with
    // the Certificate Table (Authenticode blob) excluded — signed PEs
    // would otherwise always show a giant overlay. A section without raw
    // data has no on-disk extent: the loader ignores its pointer, and so
    // must the overlay, or a pointer past the end of the file hides it.
    let sections_end: u64 = pe
        .sections
        .iter()
        .filter(|s| s.size_of_raw_data != 0)
        .map(|s| u64::from(s.pointer_to_raw_data).saturating_add(u64::from(s.size_of_raw_data)))
        .max()
        .unwrap_or(0);
    let file_size = bytes.len() as u64;
    if sections_end == 0 || sections_end >= file_size {
        return;
    }
    // Authenticode appends the table at the end of the file; one declared
    // short of the end leaves the bytes past it in the overlay.
    let overlay_end = opt
        .data_directories
        .get_certificate_table()
        .filter(|dir| {
            u64::from(dir.virtual_address).saturating_add(u64::from(dir.size)) >= file_size
        })
        .map(|dir| u64::from(dir.virtual_address))
        .filter(|&cert_start| cert_start >= sections_end && cert_start < file_size)
        .unwrap_or(file_size);
    if overlay_end <= sections_end {
        return;
    }
    metrics.insert(metric!("pe.has_overlay"), 1.0);
    metrics.insert(metric!("pe.overlay_offset"), sections_end as f64);
    metrics.insert(metric!("pe.overlay_end"), overlay_end as f64);
    metrics.insert(
        metric!("pe.overlay_size"),
        (overlay_end - sections_end) as f64,
    );
    if let Some(kind) = bytes
        .get(crate::bytes::sat_usize(sections_end)..crate::bytes::sat_usize(overlay_end))
        .and_then(crate::formats::archive_magic::archive_magic)
    {
        values.insert_key(
            value_key!("binary.overlay_archive"),
            serde_json::Value::String(kind.into()),
        );
    }
}

/// Header-arithmetic anomalies pefile flags as tampering signals.
/// Counts go on metrics; section name lists are emitted to values as
/// `pe.misaligned_sections[]` / `pe.overflowing_sections[]` /
/// `pe.overlapping_sections[]` so trait authors can match on names.
pub(super) fn section_anomalies(
    pe: &PE<'_>,
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
) {
    let file_size = bytes.len() as u64;
    let file_alignment = pe
        .header
        .optional_header
        .as_ref()
        .map_or(0, |h| h.windows_fields.file_alignment);

    let mut overflow_names: Vec<JsonValue> = Vec::new();
    let mut misaligned_names: Vec<JsonValue> = Vec::new();
    let mut bss_like: u64 = 0;
    for section in &pe.sections {
        let name = section.name().unwrap_or("");
        let raw_end = u64::from(section.pointer_to_raw_data)
            .saturating_add(u64::from(section.size_of_raw_data));
        if section.size_of_raw_data > 0 && raw_end > file_size {
            overflow_names.push(JsonValue::String(name.to_string()));
        }
        if file_alignment > 0
            && section.pointer_to_raw_data != 0
            && section.pointer_to_raw_data % file_alignment != 0
        {
            misaligned_names.push(JsonValue::String(name.to_string()));
        }
        // BSS-like: raw size zero, virtual size non-zero, name not in
        // the standard set (`.bss`/`.tls`). Standard names on legitimate
        // Borland/Delphi binaries would otherwise produce noise.
        if section.size_of_raw_data == 0 && section.virtual_size != 0 {
            let lower = name.to_ascii_lowercase();
            if !matches!(lower.as_str(), ".bss" | "bss" | ".tls" | "tls") {
                bss_like += 1;
            }
        }
    }

    metrics.insert(
        metric!("pe.section_overflow_count"),
        overflow_names.len() as f64,
    );
    metrics.insert(
        metric!("pe.misaligned_section_count"),
        misaligned_names.len() as f64,
    );
    metrics.insert(metric!("pe.bss_like_section_count"), bss_like as f64);
    if !overflow_names.is_empty() {
        values.insert_key(
            value_key!("pe.overflowing_sections"),
            JsonValue::Array(overflow_names),
        );
    }
    if !misaligned_names.is_empty() {
        values.insert_key(
            value_key!("pe.misaligned_sections"),
            JsonValue::Array(misaligned_names),
        );
    }

    // Section overlap (virtual extent intersection). O(n log n) over
    // a section count capped at ~96 by the COFF format.
    if pe.sections.len() > 1 {
        let mut by_va: Vec<(u32, u32, &str)> = pe
            .sections
            .iter()
            .map(|s| {
                let span = s.virtual_size.max(s.size_of_raw_data);
                (
                    s.virtual_address,
                    s.virtual_address.saturating_add(span),
                    s.name().unwrap_or(""),
                )
            })
            .collect();
        by_va.sort_by_key(|t| t.0);
        let mut overlap_names = std::collections::BTreeSet::new();
        for w in by_va.windows(2) {
            if let [a, b] = w
                && a.1 > b.0
                && b.0 >= a.0
            {
                overlap_names.insert(a.2);
                overlap_names.insert(b.2);
            }
        }
        if !overlap_names.is_empty() {
            metrics.insert(
                metric!("pe.section_overlap_count"),
                overlap_names.len() as f64,
            );
            values.insert_key(
                value_key!("pe.overlapping_sections"),
                JsonValue::Array(
                    overlap_names
                        .into_iter()
                        .map(|s| JsonValue::String(s.to_string()))
                        .collect(),
                ),
            );
        }
    }

    // Section count vs COFF header field — header tampering signal.
    if usize::from(pe.header.coff_header.number_of_sections) != pe.sections.len() {
        metrics.insert(metric!("pe.section_count_mismatch"), 1.0);
    }
}

/// DOS stub anomalies — the bytes between the MZ header and the PE
/// signature. Linkers stamp the canonical "This program cannot be run
/// in DOS mode" banner here; absent / zeroed regions are minor evasion
/// or hand-rolled-builder tells.
pub(super) fn dos_stub_anomalies(pe: &PE<'_>, bytes: &[u8], metrics: &mut Metrics) {
    let pe_offset = sat_usize(pe.header.dos_header.pe_pointer);
    if pe_offset <= 0x40 {
        return;
    }
    let Some(stub) = bytes.get(0x40..pe_offset) else {
        return;
    };
    if memchr::memmem::find(stub, b"This program cannot be run in DOS mode").is_none() {
        metrics.insert(metric!("pe.dos_stub_modified"), 1.0);
    }
    if stub.iter().all(|&b| b == 0) {
        metrics.insert(metric!("pe.dos_stub_zeroed"), 1.0);
    }
}

/// PE optional-header checksum. The header carries a stored value; the
/// canonical algorithm computes a 16-bit summation over the whole file
/// with the checksum field itself zeroed. Genuine binaries from
/// Microsoft / signed third-party builds match; modified payloads
/// (post-pack patches, dropper-injected code) usually don't.
///
/// Emits:
/// - `pe.checksum`           — value stored in the header.
/// - `pe.computed_checksum`  — value the algorithm produces.
/// - `pe.checksum_valid`     — 1 when the stored value matches the computed
///   one. A stored zero (linker `/RELEASE` omitted, or a packer cleared the
///   field) never matches a non-trivial file, and also sets
///   `pe.checksum_stripped`.
pub(super) fn checksum(pe: &PE<'_>, bytes: &[u8], metrics: &mut Metrics) {
    let Some(opt) = pe.header.optional_header.as_ref() else {
        return;
    };
    let stored = opt.windows_fields.check_sum;
    metrics.insert(metric!("pe.checksum"), f64::from(stored));
    let Some(checksum_offset) = layout::checksum_offset(
        sat_usize(pe.header.dos_header.pe_pointer),
        opt.standard_fields.magic,
    ) else {
        return;
    };
    if checksum_offset.saturating_add(4) > bytes.len() {
        return;
    }
    let computed = pe_checksum(bytes, checksum_offset);
    metrics.insert(metric!("pe.computed_checksum"), f64::from(computed));
    metrics.insert(
        metric!("pe.checksum_valid"),
        f64::from(u8::from(stored == computed)),
    );
    if stored == 0 {
        metrics.insert(metric!("pe.checksum_stripped"), 1.0);
    }
}

/// Microsoft's documented PE checksum algorithm: 16-bit one's-complement
/// sum over the whole file (skipping the checksum field's own 4 bytes),
/// then add the file length. Same algorithm `imagehlp.dll` /
/// `editbin /release` use.
fn pe_checksum(data: &[u8], checksum_offset: usize) -> u32 {
    let mut sum: u64 = 0;
    let mut i = 0usize;
    while i + 1 < data.len() {
        if i == checksum_offset {
            i += 4;
            continue;
        }
        let Some(word) = u16_le(data, i) else {
            break;
        };
        sum += u64::from(word);
        sum = (sum & 0xffff) + (sum >> 16);
        i += 2;
    }
    if let Some(&byte) = data.get(i) {
        sum += u64::from(byte);
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = (sum & 0xffff) + (sum >> 16);
    sum += data.len() as u64;
    // The PE checksum is 32 bits wide: the length is added modulo 2^32.
    (sum & 0xffff_ffff) as u32
}

/// Raw PE data-directory declarations and structural inconsistencies.
///
/// Goblin deliberately treats a `(0, 0)` directory as absent, which is right
/// for normal extraction. A directory with exactly one zero field is a
/// different case: it is declared in the optional header but cannot describe
/// a valid image range. Packers and import-hiding loaders use this shape to
/// leave a misleading IAT/import declaration while presenting no parseable
/// imports. Preserve it as a header fact instead of silently dropping it.
///
/// `pe.declared_data_directories[]` preserves every non-zero header slot with
/// its mapped section, even when the format parser declines to treat it as a
/// usable directory. `pe.data_directory_anomalies[]` holds the subset with a
/// zero RVA or size. The accompanying metrics are intentionally generic so
/// trait authors can detect malformed declarations without naming one
/// particular directory.
pub(super) fn data_directory_anomalies(
    pe: &PE<'_>,
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
) {
    let Some(opt) = pe.header.optional_header.as_ref() else {
        return;
    };
    let Some(directory_offset) = layout::data_directory_offset(
        sat_usize(pe.header.dos_header.pe_pointer),
        opt.standard_fields.magic,
        0,
    ) else {
        return;
    };
    let directory_count = usize::try_from(opt.windows_fields.number_of_rva_and_sizes)
        .unwrap_or(DIRECTORY_NAMES.len())
        .min(DIRECTORY_NAMES.len());

    let mut declared = Vec::new();
    let mut anomalies = Vec::new();
    let mut misplaced = 0_u32;
    let mut zero_rva_nonzero_size = 0_u64;
    let mut nonzero_rva_zero_size = 0_u64;
    for (index, name) in DIRECTORY_NAMES.iter().enumerate().take(directory_count) {
        // The original bytes rather than goblin's sparse representation, so
        // malformed declared slots survive.
        let Some(entry_offset) = directory_offset.checked_add(index * 8) else {
            break;
        };
        let (Some(rva), Some(size)) = (
            u32_le(bytes, entry_offset),
            u32_le(bytes, entry_offset.saturating_add(4)),
        ) else {
            break;
        };
        if rva == 0 && size == 0 {
            continue;
        }
        // Certificate-table addresses are file offsets by PE/COFF definition;
        // all other directory addresses are RVAs that can be mapped to a
        // section. Retain the mapping as a fact rather than assuming the
        // standard `.idata` / `.rsrc` / `.reloc` layout.
        let section = (index != CERTIFICATE_DIRECTORY)
            .then(|| layout::section_containing(&pe.sections, u64::from(rva)))
            .flatten()
            .and_then(|s| s.name().ok());
        if section
            .and_then(section_name_reserved_for)
            .is_some_and(|owner| owner != *name)
        {
            misplaced = misplaced.saturating_add(1);
        }
        declared.push(serde_json::json!({
            "index": index,
            "name": name,
            "rva": rva,
            "size": size,
            "section": section,
        }));
        if rva != 0 && size != 0 {
            continue;
        }
        let kind = if rva == 0 {
            zero_rva_nonzero_size = zero_rva_nonzero_size.saturating_add(1);
            "zero_rva_nonzero_size"
        } else {
            nonzero_rva_zero_size = nonzero_rva_zero_size.saturating_add(1);
            "nonzero_rva_zero_size"
        };
        anomalies.push(serde_json::json!({
            "index": index,
            "name": name,
            "rva": rva,
            "size": size,
            "kind": kind,
        }));
    }
    // The count is unconditional; the list is not. Zero is a real and rare
    // observation, distinct from "never parsed": every linker emits at least
    // an import directory, so a loadable image declaring none built its own
    // header and resolves imports at runtime.
    metrics.insert(
        metric!("pe.declared_data_directory_count"),
        declared.len() as f64,
    );
    // A directory parked in a section whose name is reserved for another.
    metrics.insert(
        metric!("pe.directory_section_mismatch_count"),
        f64::from(misplaced),
    );
    if !declared.is_empty() {
        values.insert_key(
            value_key!("pe.declared_data_directories"),
            JsonValue::Array(declared),
        );
    }
    if anomalies.is_empty() {
        return;
    }
    metrics.insert(
        metric!("pe.data_directory_anomaly_count"),
        anomalies.len() as f64,
    );
    if zero_rva_nonzero_size > 0 {
        metrics.insert(
            metric!("pe.data_directory_zero_rva_nonzero_size_count"),
            zero_rva_nonzero_size as f64,
        );
    }
    if nonzero_rva_zero_size > 0 {
        metrics.insert(
            metric!("pe.data_directory_nonzero_rva_zero_size_count"),
            nonzero_rva_zero_size as f64,
        );
    }
    values.insert_key(
        value_key!("pe.data_directory_anomalies"),
        JsonValue::Array(anomalies),
    );
}

#[cfg(test)]
mod tests;
