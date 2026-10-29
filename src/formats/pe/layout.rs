//! Where things sit in a PE file: raw header field offsets for the readers
//! that must see the bytes goblin normalizes away, and the one RVA → file
//! offset resolver every PE extractor shares.

use goblin::pe::PE;
use goblin::pe::header::{SIZEOF_COFF_HEADER, SIZEOF_PE_MAGIC};
use goblin::pe::optional_header::{MAGIC_32, MAGIC_64};
use goblin::pe::section_table::SectionTable;

/// Data-directory slots, by `IMAGE_DIRECTORY_ENTRY_*` index.
pub(crate) const EXPORT_DIRECTORY: usize = 0;
pub(crate) const IMPORT_DIRECTORY: usize = 1;
pub(crate) const RESOURCE_DIRECTORY: usize = 2;
pub(crate) const CERTIFICATE_DIRECTORY: usize = 4;

/// Canonical names of the sixteen data-directory slots, from winnt.h
/// `IMAGE_DIRECTORY_ENTRY_*`.
pub(super) const DIRECTORY_NAMES: [&str; 16] = [
    "export",
    "import",
    "resource",
    "exception",
    "certificate",
    "base_relocation",
    "debug",
    "architecture",
    "global_ptr",
    "tls",
    "load_config",
    "bound_import",
    "iat",
    "delay_import",
    "clr_runtime_header",
    "reserved",
];

/// File offset of the optional header in an image whose PE signature sits at
/// `pe_pointer` (`e_lfanew`): past the signature and the COFF header.
pub(crate) fn optional_header_offset(pe_pointer: usize) -> Option<usize> {
    pe_pointer.checked_add(SIZEOF_PE_MAGIC + SIZEOF_COFF_HEADER)
}

/// Offset of the data-directory array from the start of the optional header,
/// which the PE32+ 64-bit image base pushes 16 bytes further out. `None` for
/// a magic that is neither PE32 nor PE32+.
fn data_directory_start(magic: u16) -> Option<usize> {
    match magic {
        MAGIC_32 => Some(96),
        MAGIC_64 => Some(112),
        _ => None,
    }
}

/// File offset of the `NumberOfRvaAndSizes` field, the word just before the
/// data-directory array.
pub(crate) fn directory_count_offset(pe_pointer: usize, magic: u16) -> Option<usize> {
    optional_header_offset(pe_pointer)?.checked_add(data_directory_start(magic)? - 4)
}

/// File offset of data-directory slot `index`, an 8-byte `{ rva, size }`.
pub(crate) fn data_directory_offset(pe_pointer: usize, magic: u16, index: usize) -> Option<usize> {
    optional_header_offset(pe_pointer)?
        .checked_add(data_directory_start(magic)?)?
        .checked_add(index.checked_mul(8)?)
}

/// File offset of the optional header's `CheckSum`, 64 bytes in for both PE32
/// and PE32+ (the wider image base is offset by PE32's `BaseOfData`).
pub(super) fn checksum_offset(pe_pointer: usize, magic: u16) -> Option<usize> {
    data_directory_start(magic)?;
    optional_header_offset(pe_pointer)?.checked_add(64)
}

/// Map a PE RVA to the file offset the Windows loader reads it from: the
/// one RVA resolver for every PE extractor, so delay imports, relocations,
/// CLR metadata and resolver call sites all read the bytes the loader maps.
/// `None` for an RVA in no section, or in a section's zero-filled tail past
/// its file-backed bytes (memory there has no file offset).
pub(super) fn rva_to_file_offset(pe: &PE<'_>, rva: u32) -> Option<usize> {
    let file_alignment = pe
        .header
        .optional_header
        .map(|opt| opt.windows_fields.file_alignment);
    section_rva_to_file_offset(&pe.sections, file_alignment, rva)
}

/// [`rva_to_file_offset`] for a virtual address in the PE's preferred image.
pub(super) fn va_to_file_offset(pe: &PE<'_>, va: u64) -> Option<usize> {
    let rva = u32::try_from(va.checked_sub(pe.image_base)?).ok()?;
    rva_to_file_offset(pe, rva)
}

/// [`rva_to_file_offset`] over an explicit section table: the first section
/// whose file-backed extent holds `rva` wins, as in goblin's `find_offset`.
pub(super) fn section_rva_to_file_offset(
    sections: &[SectionTable],
    file_alignment: Option<u32>,
    rva: u32,
) -> Option<usize> {
    sections.iter().find_map(|section| {
        let delta = rva.checked_sub(section.virtual_address)?;
        if u64::from(delta) >= file_backed_size(section, file_alignment) {
            return None;
        }
        usize::try_from(aligned_raw_pointer(section) + u64::from(delta)).ok()
    })
}

/// `PointerToRawData` as the loader uses it: rounded down to 512 bytes
/// whatever the header claims (Peter Ferrie, "Reliable algorithm to extract
/// overlay of a PE"; goblin's `aligned_pointer_to_raw_data`).
fn aligned_raw_pointer(section: &SectionTable) -> u64 {
    u64::from(section.pointer_to_raw_data) & !0x1ff
}

/// How many bytes of `section`, from its RVA, the loader reads from the file:
/// the raw extent rounded up to the file alignment, capped by the raw and
/// virtual sizes rounded up to a page. goblin's `section_read_size`, in
/// overflow-free arithmetic; an invalid alignment leaves the raw extent
/// unrounded instead of resolving nothing.
pub(super) fn file_backed_size(section: &SectionTable, file_alignment: Option<u32>) -> u64 {
    let raw = u64::from(section.size_of_raw_data);
    if raw == 0 {
        return 0;
    }
    let page = |size: u64| size.next_multiple_of(0x1000);
    let raw_end = u64::from(section.pointer_to_raw_data) + raw;
    let raw_end = match file_alignment.filter(|a| a.is_power_of_two()) {
        Some(alignment) => raw_end.next_multiple_of(u64::from(alignment)),
        None => raw_end,
    };
    let read = (raw_end - aligned_raw_pointer(section)).min(page(raw));
    match section.virtual_size {
        0 => read,
        virtual_size => read.min(page(u64::from(virtual_size))),
    }
}

/// The section whose virtual extent (`max(VirtualSize, SizeOfRawData)`)
/// holds `rva`, first match winning.
pub(super) fn section_containing(sections: &[SectionTable], rva: u64) -> Option<&SectionTable> {
    sections.iter().find(|s| {
        let start = u64::from(s.virtual_address);
        let span = u64::from(s.virtual_size).max(u64::from(s.size_of_raw_data));
        rva >= start && rva < start.saturating_add(span)
    })
}

/// Raw bytes of a named PE section (e.g. `.gopclntab`, `.rdata`).
pub(super) fn section_bytes<'a>(pe: &PE<'_>, bytes: &'a [u8], name: &str) -> Option<&'a [u8]> {
    let section = pe.sections.iter().find(|s| s.name().ok() == Some(name))?;
    let start = section.pointer_to_raw_data as usize;
    let size = section.size_of_raw_data as usize;
    bytes.get(start..start.checked_add(size)?)
}

#[cfg(test)]
mod tests;
