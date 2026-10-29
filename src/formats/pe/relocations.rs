//! The base-relocation directory, and how much of its section it fills.

use goblin::pe::PE;

use super::layout::{rva_to_file_offset, section_containing};
use crate::formats::common::bytes_at::{u16_le, u32_le};
use crate::metric;
use crate::output::{Metrics, Values};
use crate::value_key;

/// Walk the base-relocation directory (data dir index 5) and count
/// the relocation entries. ASLR-aware binaries carry a populated
/// relocation table; packed / hand-rolled binaries often strip or
/// truncate it. The block structure is a sequence of
/// `IMAGE_BASE_RELOCATION { page_rva: DWORD, block_size: DWORD }`
/// each followed by `(block_size-8)/2` WORD entries (4-bit type +
/// 12-bit offset).
pub(super) fn base_relocations(
    pe: &PE<'_>,
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
) {
    let Some(opt) = pe.header.optional_header.as_ref() else {
        return;
    };
    let Some(dd) = opt.data_directories.get_base_relocation_table() else {
        return;
    };
    if dd.virtual_address == 0 || dd.size == 0 {
        return;
    }
    let Some(start) = rva_to_file_offset(pe, dd.virtual_address) else {
        return;
    };
    let end = start.saturating_add(dd.size as usize).min(bytes.len());
    let mut cursor = start;
    let mut block_count = 0_u64;
    let mut entry_count = 0_u64;
    let mut absolute_count = 0_u64; // type 0 — pure padding, no real reloc
    while cursor + 8 <= end {
        // The block header is `{ page_rva: u32, block_size: u32 }`; only the
        // size matters here.
        let Some(block_size) = u32_le(bytes, cursor + 4).map(|v| v as usize) else {
            break;
        };
        if block_size < 8 || cursor + block_size > end {
            break;
        }
        block_count += 1;
        let entries = (block_size - 8) / 2;
        for i in 0..entries {
            let off = cursor + 8 + i * 2;
            if off + 2 > end {
                break;
            }
            let Some(word) = u16_le(bytes, off) else {
                break;
            };
            let kind = word >> 12;
            if kind == 0 {
                absolute_count += 1;
            } else {
                entry_count += 1;
            }
        }
        cursor += block_size;
    }
    if block_count > 0 {
        values.insert_key(
            value_key!("pe.base_relocations"),
            serde_json::json!({
                "block_count": block_count,
                "entry_count": entry_count,
                "padding_count": absolute_count,
            }),
        );
        metrics.insert(
            metric!("pe.base_relocation_block_count"),
            block_count as f64,
        );
        metrics.insert(
            metric!("pe.base_relocation_entry_count"),
            entry_count as f64,
        );
    }

    // Reloc-section overhang: how much of the section that hosts the base-
    // relocation directory is NOT actual relocation data. Real relocation
    // tables fill their `.reloc` section (modulo a sub-alignment tail). Packers
    // and trojanized loaders append an encrypted second stage to `.reloc` so the
    // section dwarfs the few real relocation blocks — the parser stops at the
    // first malformed block (or the directory end) far short of the section's
    // raw size. `overhang_ratio` is that gap as a fraction of the section, a
    // precise, format-level "payload concealed in .reloc" signal that does not
    // depend on the payload's entropy. ~0 for benign images.
    let parsed_bytes = (cursor - start) as u64;
    if let Some(section) = section_containing(&pe.sections, u64::from(dd.virtual_address)) {
        let section_raw = u64::from(section.size_of_raw_data);
        if section_raw > 0 {
            let overhang = section_raw.saturating_sub(parsed_bytes);
            metrics.insert(metric!("pe.relocation_overhang_bytes"), overhang as f64);
            metrics.insert(
                metric!("pe.relocation_overhang_ratio"),
                overhang as f64 / section_raw as f64,
            );
        }
    }
}
