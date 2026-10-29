//! DOS, COFF and optional-header facts, the section table, and the
//! data-directory inventory.

use goblin::pe::PE;
use goblin::pe::header::{CoffHeader, Header};
use goblin::pe::optional_header::OptionalHeader;
use serde_json::Value as JsonValue;

use super::layout::DIRECTORY_NAMES;
use crate::formats::common::{put_i64, put_str, put_u64, section_entropy};
use crate::metric;
use crate::output::{Metrics, Section, SectionFlag, Values};
use crate::value_key;

/// `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`: the image opts into ASLR.
const DYNAMIC_BASE: u16 = 0x0040;

pub(super) fn coff_header(coff: &CoffHeader, values: &mut Values, metrics: &mut Metrics) {
    // COFF and optional-header fields land directly under `pe.*`: the
    // spec's two-header partitioning is plumbing a reader need not navigate.
    put_str(
        values,
        value_key!("pe.machine"),
        machine_string(coff.machine),
    );
    // Raw COFF machine + characteristics words, stable across PE revisions,
    // beside the string projections.
    put_u64(values, value_key!("pe.machine_id"), u64::from(coff.machine));
    put_u64(
        values,
        value_key!("pe.characteristics_raw"),
        u64::from(coff.characteristics),
    );
    // `TimeDateStamp` is a 32-bit Unix timestamp, widened so values past
    // 2038 survive whichever signedness a linker meant. The section count is
    // `sections.count`; NumberOfSections would only duplicate it.
    put_i64(
        values,
        value_key!("pe.timestamp"),
        i64::from(coff.time_date_stamp),
    );
    metrics.insert(metric!("pe.timestamp"), f64::from(coff.time_date_stamp));
    // COFF symbol-table pointer + entry count. Modern toolchains zero
    // both (debug info goes to PDBs), so a non-zero pair flags an
    // older or unusual build.
    put_u64(
        values,
        value_key!("pe.coff.symbol_table_offset"),
        u64::from(coff.pointer_to_symbol_table),
    );
    put_u64(
        values,
        value_key!("pe.coff.symbol_count"),
        u64::from(coff.number_of_symbol_table),
    );
    let characteristics: Vec<JsonValue> = coff_characteristics(coff.characteristics)
        .into_iter()
        .map(|s| JsonValue::String(s.into()))
        .collect();
    values.insert_key(
        value_key!("pe.characteristics"),
        JsonValue::Array(characteristics),
    );
}

/// `e_lfanew`, the offset to the PE signature, which bounds the DOS stub and
/// the Rich header inside it.
pub(super) fn dos_header(header: &Header<'_>, values: &mut Values) {
    put_u64(
        values,
        value_key!("pe.coff.dos_header_pe_pointer"),
        u64::from(header.dos_header.pe_pointer),
    );
}

pub(super) fn optional_header(opt: &OptionalHeader, values: &mut Values, metrics: &mut Metrics) {
    let standard = &opt.standard_fields;
    let windows = &opt.windows_fields;

    put_str(
        values,
        value_key!("pe.subsystem"),
        subsystem_string(windows.subsystem),
    );
    put_u64(values, value_key!("pe.image_base"), windows.image_base);
    put_u64(
        values,
        value_key!("pe.image_size"),
        u64::from(windows.size_of_image),
    );
    metrics.insert(metric!("pe.image_size"), f64::from(windows.size_of_image));
    put_u64(
        values,
        value_key!("pe.headers_size"),
        u64::from(windows.size_of_headers),
    );
    put_u64(
        values,
        value_key!("pe.entry_point"),
        u64::from(standard.address_of_entry_point),
    );
    put_str(
        values,
        value_key!("pe.subsystem_version"),
        format!(
            "{}.{}",
            windows.major_subsystem_version, windows.minor_subsystem_version
        ),
    );
    put_str(
        values,
        value_key!("pe.os_version"),
        format!(
            "{}.{}",
            windows.major_operating_system_version, windows.minor_operating_system_version
        ),
    );
    // Raw optional-header words beside the string projections above.
    put_u64(
        values,
        value_key!("pe.subsystem_raw"),
        u64::from(windows.subsystem),
    );
    put_u64(
        values,
        value_key!("pe.dll_characteristics_raw"),
        u64::from(windows.dll_characteristics),
    );
    put_u64(
        values,
        value_key!("pe.file_alignment"),
        u64::from(windows.file_alignment),
    );
    metrics.insert(
        metric!("pe.file_alignment"),
        f64::from(windows.file_alignment),
    );
    put_u64(
        values,
        value_key!("pe.section_alignment"),
        u64::from(windows.section_alignment),
    );
    put_u64(
        values,
        value_key!("pe.linker_major_version"),
        u64::from(standard.major_linker_version),
    );
    put_u64(
        values,
        value_key!("pe.linker_minor_version"),
        u64::from(standard.minor_linker_version),
    );
    put_u64(
        values,
        value_key!("pe.data_directory_count"),
        u64::from(windows.number_of_rva_and_sizes),
    );
    let dll_chars: Vec<JsonValue> = dll_characteristics(windows.dll_characteristics)
        .into_iter()
        .map(|s| JsonValue::String(s.into()))
        .collect();
    values.insert_key(
        value_key!("pe.dll_characteristics"),
        JsonValue::Array(dll_chars),
    );
    // The cross-format `binary.is_pie`: without DYNAMIC_BASE the loader fixes
    // the image at `image_base`, the PE equivalent of a non-PIE executable.
    let is_pie = windows.dll_characteristics & DYNAMIC_BASE != 0;
    metrics.insert(metric!("binary.is_pie"), f64::from(u8::from(is_pie)));
}

pub(super) fn sections(pe: &PE<'_>, bytes: &[u8], sections_out: &mut Vec<Section>) {
    for section in &pe.sections {
        let name = section.name().unwrap_or("").to_owned();
        let file_offset = u64::from(section.pointer_to_raw_data);
        let file_size = u64::from(section.size_of_raw_data);
        let entropy = (file_size > 0).then(|| section_entropy(bytes, file_offset, file_size));
        sections_out.push(Section {
            name,
            vaddr: u64::from(section.virtual_address),
            vsize: u64::from(section.virtual_size),
            file_offset,
            file_size,
            flags: section_characteristics(section.characteristics),
            flags_raw: Some(u64::from(section.characteristics)),
            entropy,
        });
    }
}

/// The optional header's non-empty data-directory slots as
/// `pe.data_directories[]`, keyed by canonical name rather than index.
/// goblin treats a zeroed slot as absent; the raw declarations, zeroed and
/// malformed ones included, are `pe.declared_data_directories`.
pub(super) fn data_directories(pe: &PE<'_>, values: &mut Values) {
    let Some(opt) = pe.header.optional_header.as_ref() else {
        return;
    };
    let mut entries: Vec<JsonValue> = Vec::new();
    for (idx, slot) in opt.data_directories.data_directories.iter().enumerate() {
        let Some((_, dir)) = slot.as_ref() else {
            continue;
        };
        if dir.virtual_address == 0 && dir.size == 0 {
            continue;
        }
        let name = DIRECTORY_NAMES.get(idx).copied().unwrap_or("unknown");
        entries.push(serde_json::json!({
            "name": name,
            "rva": dir.virtual_address,
            "size": dir.size,
        }));
    }
    if !entries.is_empty() {
        values.insert_key(value_key!("pe.data_directories"), JsonValue::Array(entries));
    }
}

fn machine_string(machine: u16) -> &'static str {
    // Constants from winnt.h `IMAGE_FILE_MACHINE_*`.
    match machine {
        0x014c => "i386",
        0x0162 => "r3000",
        0x0166 => "r4000",
        0x0168 => "r10000",
        0x0169 => "wcemipsv2",
        0x0184 => "alpha",
        0x01a2 => "sh3",
        0x01a3 => "sh3dsp",
        0x01a6 => "sh4",
        0x01a8 => "sh5",
        0x01c0 => "arm",
        0x01c2 => "thumb",
        0x01c4 => "armnt",
        0x01d3 => "am33",
        0x01f0 => "powerpc",
        0x01f1 => "powerpcfp",
        0x0200 => "ia64",
        0x0266 => "mips16",
        0x0284 => "alpha64",
        0x0366 => "mipsfpu",
        0x0466 => "mipsfpu16",
        0x0520 => "tricore",
        0x0cef => "cef",
        0x0ebc => "ebc",
        0x8664 => "x86_64",
        0x9041 => "m32r",
        0xaa64 => "arm64",
        0xc0ee => "cee",
        _ => "unknown",
    }
}

fn coff_characteristics(flags: u16) -> Vec<&'static str> {
    // From winnt.h `IMAGE_FILE_*`. The forensically relevant subset; the
    // rarely set DEBUG_STRIPPED and NET_RUN_FROM_SWAP are omitted.
    [
        (0x0001, "relocs_stripped"),
        (0x0002, "executable_image"),
        (0x0020, "large_address_aware"),
        (0x0100, "32bit_machine"),
        (0x1000, "system_image"),
        (0x2000, "dll"),
    ]
    .into_iter()
    .filter_map(|(bit, name)| (flags & bit != 0).then_some(name))
    .collect()
}

fn dll_characteristics(flags: u16) -> Vec<&'static str> {
    // From winnt.h `IMAGE_DLLCHARACTERISTICS_*`.
    [
        (0x0020, "high_entropy_va"),
        (DYNAMIC_BASE, "dynamic_base"),
        (0x0080, "force_integrity"),
        (0x0100, "nx_compat"),
        (0x0200, "no_isolation"),
        (0x0400, "no_seh"),
        (0x0800, "no_bind"),
        (0x1000, "app_container"),
        (0x2000, "wdm_driver"),
        (0x4000, "guard_cf"),
        (0x8000, "terminal_server_aware"),
    ]
    .into_iter()
    .filter_map(|(bit, name)| (flags & bit != 0).then_some(name))
    .collect()
}

fn subsystem_string(subsystem: u16) -> &'static str {
    // From winnt.h `IMAGE_SUBSYSTEM_*`. `0` (the explicit "unknown"
    // constant) collapses into the default arm — same string, same
    // meaning, no semantic loss.
    match subsystem {
        1 => "native",
        2 => "windows_gui",
        3 => "windows_cui",
        5 => "os2_cui",
        7 => "posix_cui",
        8 => "native_windows",
        9 => "windows_ce_gui",
        10 => "efi_application",
        11 => "efi_boot_service_driver",
        12 => "efi_runtime_driver",
        13 => "efi_rom",
        14 => "xbox",
        16 => "windows_boot_application",
        _ => "unknown",
    }
}

fn section_characteristics(flags: u32) -> Vec<SectionFlag> {
    [
        (0x0000_0020, SectionFlag::Code),
        (0x0000_0040, SectionFlag::InitializedData),
        (0x0000_0080, SectionFlag::UninitializedData),
        (0x2000_0000, SectionFlag::Executable),
        (0x4000_0000, SectionFlag::Readable),
        (0x8000_0000, SectionFlag::Writable),
    ]
    .into_iter()
    .filter_map(|(bit, flag)| (flags & bit != 0).then_some(flag))
    .collect()
}

#[cfg(test)]
mod tests;
