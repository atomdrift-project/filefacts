//! Where things sit in a PE file: raw header field offsets for the readers
//! that must see the bytes goblin normalizes away, and the one RVA → file
//! offset resolver every PE extractor shares.

use goblin::pe::PE;
use goblin::pe::header::{SIZEOF_COFF_HEADER, SIZEOF_PE_MAGIC};
use goblin::pe::optional_header::{MAGIC_32, MAGIC_64};
use goblin::pe::section_table::SectionTable;

/// Data-directory slots, by `IMAGE_DIRECTORY_ENTRY_*` index.
pub(crate) const EXPORT_DIRECTORY: usize = 0;
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

/// File offset of data-directory slot `index`, an 8-byte `{ rva, size }`.
pub(crate) fn data_directory_offset(pe_pointer: usize, magic: u16, index: usize) -> Option<usize> {
    optional_header_offset(pe_pointer)?
        .checked_add(data_directory_start(magic)?)?
        .checked_add(index.checked_mul(8)?)
}

/// The image base and COFF `Machine` the raw headers declare, zero where
/// they do not reach: for placing binform's views of a PE whose headers
/// goblin could not parse.
pub(super) fn base_and_machine(bytes: &[u8]) -> (u64, u16) {
    use crate::bytes::{u16_le, u32_le, u64_le};
    let pe_pointer = u32_le(bytes, 0x3c).map(crate::bytes::sat_usize);
    let machine = pe_pointer
        .and_then(|at| u16_le(bytes, at.checked_add(SIZEOF_PE_MAGIC)?))
        .unwrap_or(0);
    let base = pe_pointer
        .and_then(optional_header_offset)
        .and_then(|optional| match u16_le(bytes, optional)? {
            MAGIC_32 => u32_le(bytes, optional.checked_add(28)?).map(u64::from),
            MAGIC_64 => u64_le(bytes, optional.checked_add(24)?),
            _ => None,
        })
        .unwrap_or(0);
    (base, machine)
}

/// File offset of the optional header's `CheckSum`, 64 bytes in for both PE32
/// and PE32+ (the wider image base is offset by PE32's `BaseOfData`).
pub(super) fn checksum_offset(pe_pointer: usize, magic: u16) -> Option<usize> {
    data_directory_start(magic)?;
    optional_header_offset(pe_pointer)?.checked_add(64)
}

/// Most section headers any PE reader here takes from a table. The PE
/// specification caps the count at 96 and Windows tolerates somewhat more;
/// a four-figure count is a forged header.
pub(crate) const MAX_SECTIONS: usize = 192;

/// Map a PE RVA to the file offset the Windows loader reads it from: the
/// one RVA resolver for every PE extractor, so delay imports, relocations,
/// CLR metadata and resolver call sites all read the bytes the loader maps.
/// `None` for an RVA in no section, or in a section's zero-filled tail past
/// its file-backed bytes (memory there has no file offset).
pub(super) fn rva_to_file_offset(pe: &PE<'_>, rva: u32) -> Option<usize> {
    resolve(&pe.sections, file_alignment(pe), rva).map(|(_, offset, _)| offset)
}

/// The optional header's `FileAlignment`, when there is an optional header.
pub(super) fn file_alignment(pe: &PE<'_>) -> Option<u32> {
    pe.header
        .optional_header
        .map(|opt| opt.windows_fields.file_alignment)
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
    resolve(sections, file_alignment, rva).map(|(_, offset, _)| offset)
}

/// The section the loader reads `rva` from, the file offset it reads it at,
/// and how many bytes from there the section backs: the first section whose
/// file-backed extent holds `rva`.
pub(super) fn resolve(
    sections: &[SectionTable],
    file_alignment: Option<u32>,
    rva: u32,
) -> Option<(&SectionTable, usize, u64)> {
    sections.iter().find_map(|section| {
        let delta = u64::from(rva.checked_sub(section.virtual_address)?);
        let backed = file_backed_size(section, file_alignment);
        if delta >= backed {
            return None;
        }
        let offset = usize::try_from(aligned_raw_pointer(section) + delta).ok()?;
        Some((section, offset, backed - delta))
    })
}

/// The bytes the loader maps for `section`, from the file: [`resolve`]'s
/// extent of the section's own first byte, cut at the end of the file.
pub(super) fn section_data<'a>(
    section: &SectionTable,
    file_alignment: Option<u32>,
    bytes: &'a [u8],
) -> Option<&'a [u8]> {
    let start = usize::try_from(aligned_raw_pointer(section)).ok()?;
    let len = usize::try_from(file_backed_size(section, file_alignment)).ok()?;
    let rest = bytes.get(start..)?;
    (len > 0).then(|| rest.get(..len).unwrap_or(rest))
}

/// binform's reading of a PE section table as goblin's section headers, for
/// the readers that run when goblin could not parse the image. Long `/n`
/// names stay binform's resolved ones, cut to the eight bytes a header
/// holds.
pub(super) fn section_table(layout: &binform::Binary<'_>, image_base: u64) -> Vec<SectionTable> {
    layout
        .sections()
        .iter()
        .take(MAX_SECTIONS)
        .map(|section| {
            let mut name = [0; 8];
            for (to, from) in name.iter_mut().zip(section.name.bytes()) {
                *to = from;
            }
            SectionTable {
                name,
                real_name: Some(section.name.clone()),
                virtual_size: crate::bytes::sat_u32(section.size),
                virtual_address: crate::bytes::sat_u32(section.addr.wrapping_sub(image_base)),
                size_of_raw_data: crate::bytes::sat_u32(section.file_size),
                pointer_to_raw_data: crate::bytes::sat_u32(section.offset),
                characteristics: crate::bytes::sat_u32(section.flags),
                ..SectionTable::default()
            }
        })
        .collect()
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

/// The bytes the loader maps for the first section named `name` (e.g.
/// `.gopclntab`, `.rdata`).
pub(super) fn section_bytes<'a>(pe: &PE<'_>, bytes: &'a [u8], name: &str) -> Option<&'a [u8]> {
    let section = pe.sections.iter().find(|s| s.name().ok() == Some(name))?;
    section_data(section, file_alignment(pe), bytes)
}

#[cfg(test)]
mod tests;
