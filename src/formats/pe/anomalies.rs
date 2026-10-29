//! Header arithmetic that does not add up: section extents past the file,
//! misalignment and overlap, an entry point outside the code, overlays, a
//! rewritten DOS stub, a stale checksum, and malformed data directories.

use goblin::pe::PE;
use goblin::pe::header::Header;
use serde_json::Value as JsonValue;

use super::layout::{self, CERTIFICATE_DIRECTORY, DIRECTORY_NAMES};
use crate::formats::common::bytes_at::{u16_le, u32_le};
use crate::formats::common::put_str;
use crate::metric;
use crate::output::{Metrics, Values};
use crate::value_key;

/// `IMAGE_SCN_MEM_WRITE`.
const SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Section extents past the end of the file, read from the raw section table
/// when goblin could not parse the image. Only a complete, bounded table
/// counts: a truncated one says nothing about how many sections overflow.
pub(super) fn partial_section_overflows(
    bytes: &[u8],
    header: &Header<'_>,
    values: &mut Values,
    metrics: &mut Metrics,
) {
    let count = usize::from(header.coff_header.number_of_sections);
    if count == 0 || count > 96 {
        return;
    }
    let Some(start) = layout::optional_header_offset(header.dos_header.pe_pointer as usize)
        .and_then(|optional| {
            optional.checked_add(usize::from(header.coff_header.size_of_optional_header))
        })
    else {
        return;
    };
    let Some(end) = count.checked_mul(40).and_then(|n| start.checked_add(n)) else {
        return;
    };
    let Some(table) = bytes.get(start..end) else {
        tracing::debug!(
            target: "filefacts::pe",
            format = "pe",
            stage = "section-table",
            offset = start,
            len = end - start,
            "section table runs past the file; overflow count not reported"
        );
        return;
    };
    let mut names = Vec::new();
    for section in table.as_chunks::<40>().0 {
        let (Some(size), Some(offset)) = (u32_le(section, 16), u32_le(section, 20)) else {
            return;
        };
        if size != 0 && u64::from(offset) + u64::from(size) > bytes.len() as u64 {
            let name = section[..8].split(|&b| b == 0).next().unwrap_or_default();
            names.push(JsonValue::String(
                String::from_utf8_lossy(name).into_owned(),
            ));
        }
    }
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
///   `pe.overlay_end` — overlay extent in file-offset space.
///
/// Emits to values:
/// - `pe.entry_section` — name of the section containing the EP RVA.
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
        if section.characteristics & SCN_MEM_WRITE != 0 {
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
    // would otherwise always show a giant overlay.
    let sections_end: u64 = pe
        .sections
        .iter()
        .map(|s| u64::from(s.pointer_to_raw_data).saturating_add(u64::from(s.size_of_raw_data)))
        .max()
        .unwrap_or(0);
    let file_size = bytes.len() as u64;
    if sections_end == 0 || sections_end >= file_size {
        return;
    }
    let overlay_end = opt
        .data_directories
        .get_certificate_table()
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
    let pe_offset = pe.header.dos_header.pe_pointer as usize;
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
        pe.header.dos_header.pe_pointer as usize,
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
        pe.header.dos_header.pe_pointer as usize,
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
