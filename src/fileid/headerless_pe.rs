//! PE images whose header magics were wiped after mapping.
//!
//! A loader that maps a PE itself (Smoke Loader / Dofoil's later stages,
//! reflective loaders, process hollowers) does not need the `MZ` at offset 0,
//! the `e_lfanew` at 0x3C or the `PE\0\0` signature, and often zeroes or
//! overwrites them -- along with other fields only the Windows loader reads:
//! the machine, the optional-header size and magic, the alignments and the
//! data-directory count. Smoke's bot image keeps `e_lfanew` in its first
//! dword instead. Without the magics the bytes read as opaque data, and
//! neither PE parsing nor PE-scoped rules ever see the program.
//!
//! [`locate`] finds such an image only when the rest of its headers still
//! describe a loadable program: a section table inside the headers, sections
//! aligned, ascending, inside `SizeOfImage` and (when stored) inside the file,
//! a 64 KiB-aligned image base, an entry point inside a section and data
//! directories inside the image. Every field that survived must agree with
//! the layout the others imply. Random, text and zero-filled data fail it.
//!
//! [`repair`] returns a copy with the wiped fields restored -- the values
//! being fixed by the structure the image still has -- so the PE parser reads
//! the program the loader would. The copy has the input's length, so every
//! file offset still names the same byte. The fields restored are reported:
//! a wiped header is itself a strong signal.

use memchr::memmem;

use crate::bytes::{u16_le, u32_le, u64_le};

/// `e_lfanew` lies past the 64-byte DOS header and inside the first page.
const MIN_NT_OFFSET: usize = 0x40;
const MAX_NT_OFFSET: usize = 0x1000;
/// How far an intact `PE\0\0` is looked for when `e_lfanew` is gone too.
const SIGNATURE_WINDOW: usize = 0x400;
/// `IMAGE_NUMBEROF_DIRECTORY_ENTRIES`.
const DIRECTORY_ENTRIES: u32 = 16;
/// The certificate-table directory holds a file offset, not an RVA.
const SECURITY_DIRECTORY: u32 = 4;
/// The section count a loader accepts.
const MAX_SECTIONS: usize = 96;
/// `IMAGE_SIZEOF_SECTION_HEADER`.
const SECTION_HEADER: usize = 40;
/// A loadable image base is a multiple of 64 KiB.
const IMAGE_BASE_ALIGNMENT: u64 = 0x1_0000;
/// The alignments a wiped header is restored to: the linker defaults.
const DEFAULT_SECTION_ALIGNMENT: u32 = 0x1000;
const DEFAULT_FILE_ALIGNMENT: u32 = 0x200;
/// The largest alignment the PE format allows.
const MAX_ALIGNMENT: u32 = 0x1_0000;

/// A header field [`repair`] restored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Field {
    /// `MZ` at offset 0.
    DosMagic,
    /// `e_lfanew` at 0x3C.
    NtOffset,
    /// `PE\0\0` at `e_lfanew`.
    NtSignature,
    /// `IMAGE_FILE_HEADER.Machine`, inferred from the optional-header layout
    /// (i386 for PE32, x86-64 for PE32+).
    Machine,
    /// `IMAGE_FILE_HEADER.SizeOfOptionalHeader`.
    OptionalHeaderSize,
    /// `IMAGE_OPTIONAL_HEADER.Magic`.
    OptionalMagic,
    /// `SectionAlignment`.
    SectionAlignment,
    /// `FileAlignment`.
    FileAlignment,
    /// `NumberOfRvaAndSizes`.
    DataDirectoryCount,
}

impl Field {
    /// The field's name in the `pe.header.repaired` fact.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::DosMagic => "dos_magic",
            Self::NtOffset => "nt_offset",
            Self::NtSignature => "nt_signature",
            Self::Machine => "machine",
            Self::OptionalHeaderSize => "optional_header_size",
            Self::OptionalMagic => "optional_magic",
            Self::SectionAlignment => "section_alignment",
            Self::FileAlignment => "file_alignment",
            Self::DataDirectoryCount => "data_directory_count",
        }
    }
}

/// The optional-header layout: PE32 or PE32+.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Layout {
    Pe32,
    Pe64,
}

impl Layout {
    fn magic(self) -> u16 {
        match self {
            Self::Pe32 => 0x010B,
            Self::Pe64 => 0x020B,
        }
    }

    /// The optional-header size with all sixteen data directories.
    fn optional_header_size(self) -> u16 {
        match self {
            Self::Pe32 => 0xE0,
            Self::Pe64 => 0xF0,
        }
    }

    /// Offset of `NumberOfRvaAndSizes`; the directories follow it.
    fn directory_count_offset(self) -> usize {
        match self {
            Self::Pe32 => 92,
            Self::Pe64 => 108,
        }
    }

    /// The machines built with this layout.
    fn machines(self) -> &'static [u16] {
        match self {
            Self::Pe32 => &[
                0x014C, // i386
                0x01C0, // ARM LE
                0x01C2, // ARM Thumb
                0x01C4, // ARM Thumb-2 / ARMv7
                0x0166, // MIPS R4000
                0x0366, // MIPS FPU
                0x0466, // MIPS FPU16
                0x5032, // RISC-V 32
            ],
            Self::Pe64 => &[
                0x8664, // x86-64
                0xAA64, // ARM64
                0x0200, // IA-64
                0x5064, // RISC-V 64
            ],
        }
    }

    /// The machine a wiped one is restored to.
    fn default_machine(self) -> u16 {
        match self {
            Self::Pe32 => 0x014C,
            Self::Pe64 => 0x8664,
        }
    }

    fn image_base(self, data: &[u8], optional: usize) -> Option<u64> {
        match self {
            Self::Pe32 => u32_le(data, optional.checked_add(28)?).map(u64::from),
            Self::Pe64 => u64_le(data, optional.checked_add(24)?),
        }
    }
}

/// A validated wiped header: where its NT headers are, their layout, and
/// what restoring them takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Header {
    nt_offset: usize,
    layout: Layout,
    section_alignment: u32,
    file_alignment: u32,
    fields: Vec<Field>,
}

impl Header {
    /// The offset of the NT headers (the restored `e_lfanew`).
    pub(crate) fn nt_offset(&self) -> usize {
        self.nt_offset
    }

    /// The fields restoring the header rewrites, in header order.
    pub(crate) fn fields(&self) -> &[Field] {
        &self.fields
    }
}

/// A wiped PE header restored: the image with its header rewritten, and
/// what was rewritten.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Repaired {
    /// The input with the restored fields written in; same length.
    pub(crate) image: Vec<u8>,
    /// The header that was restored.
    pub(crate) header: Header,
}

/// The wiped PE header of `data`, when its magics are missing but the rest
/// of the headers describe a loadable program. An image whose `MZ`,
/// `e_lfanew` and `PE\0\0` are all intact is an ordinary PE: `None`.
///
/// The NT headers are looked for where `e_lfanew` says, where Smoke Loader
/// keeps it (the first dword), and at any 4-aligned `PE\0\0` in the first
/// KiB.
pub(crate) fn locate(data: &[u8]) -> Option<Header> {
    let dword = |at: usize| u32_le(data, at).and_then(|v| usize::try_from(v).ok());
    let signatures = memmem::find_iter(data.get(..SIGNATURE_WINDOW).unwrap_or(data), b"PE\0\0");
    [dword(0x3C), dword(0)]
        .into_iter()
        .flatten()
        .chain(signatures)
        .find_map(|nt| header_at(data, nt))
}

/// [`locate`], then the image with the header restored.
pub(crate) fn repair(data: &[u8]) -> Option<Repaired> {
    let header = locate(data)?;
    let mut image = data.to_vec();
    let nt = header.nt_offset;
    let coff = nt.checked_add(4)?;
    let optional = coff.checked_add(20)?;
    let layout = header.layout;
    for &field in &header.fields {
        let (at, bytes): (usize, &[u8]) = match field {
            Field::DosMagic => (0, b"MZ"),
            Field::NtOffset => (0x3C, &u32::try_from(nt).ok()?.to_le_bytes()),
            Field::NtSignature => (nt, b"PE\0\0"),
            Field::Machine => (coff, &layout.default_machine().to_le_bytes()),
            Field::OptionalHeaderSize => (
                coff.checked_add(16)?,
                &layout.optional_header_size().to_le_bytes(),
            ),
            Field::OptionalMagic => (optional, &layout.magic().to_le_bytes()),
            Field::SectionAlignment => (
                optional.checked_add(32)?,
                &header.section_alignment.to_le_bytes(),
            ),
            Field::FileAlignment => (
                optional.checked_add(36)?,
                &header.file_alignment.to_le_bytes(),
            ),
            Field::DataDirectoryCount => (
                optional.checked_add(layout.directory_count_offset())?,
                &DIRECTORY_ENTRIES.to_le_bytes(),
            ),
        };
        image
            .get_mut(at..at.checked_add(bytes.len())?)?
            .copy_from_slice(bytes);
    }
    Some(Repaired { image, header })
}

/// The wiped header whose NT headers start at `nt`: exactly one layout must
/// fit, or the bytes are not a program this module can vouch for.
fn header_at(data: &[u8], nt: usize) -> Option<Header> {
    if !(MIN_NT_OFFSET..=MAX_NT_OFFSET).contains(&nt) || !nt.is_multiple_of(4) {
        return None;
    }
    let signature = data.get(nt..nt.checked_add(4)?)?;
    let signature_intact = signature == b"PE\0\0";
    if !signature_intact && signature != [0; 4] {
        return None;
    }
    let mut fields = Vec::new();
    if !data.starts_with(b"MZ") {
        fields.push(Field::DosMagic);
    }
    if u32_le(data, 0x3C).and_then(|v| usize::try_from(v).ok()) != Some(nt) {
        fields.push(Field::NtOffset);
    }
    if !signature_intact {
        fields.push(Field::NtSignature);
    }
    if fields.is_empty() {
        return None;
    }
    let mut fits = [Layout::Pe32, Layout::Pe64]
        .into_iter()
        .filter_map(|layout| fit(data, nt, layout, fields.clone()));
    let header = fits.next()?;
    fits.next().is_none().then_some(header)
}

/// Validate the NT headers at `nt` as `layout`, adding to `fields` each
/// further field restoring them takes.
fn fit(data: &[u8], nt: usize, layout: Layout, mut fields: Vec<Field>) -> Option<Header> {
    let u16_at = |at: usize| u16_le(data, at);
    let u32_at = |at: usize| u32_le(data, at).map(u64::from);
    let coff = nt.checked_add(4)?;
    let optional = coff.checked_add(20)?;

    match u16_at(coff)? {
        0 => fields.push(Field::Machine),
        machine if layout.machines().contains(&machine) => {}
        _ => return None,
    }
    let sections = usize::from(u16_at(coff.checked_add(2)?)?);
    if !(1..=MAX_SECTIONS).contains(&sections) {
        return None;
    }
    match u16_at(coff.checked_add(16)?)? {
        0 => fields.push(Field::OptionalHeaderSize),
        size if size == layout.optional_header_size() => {}
        _ => return None,
    }
    match u16_at(optional)? {
        0 => fields.push(Field::OptionalMagic),
        magic if magic == layout.magic() => {}
        _ => return None,
    }
    let image_base = layout.image_base(data, optional)?;
    if image_base == 0 || !image_base.is_multiple_of(IMAGE_BASE_ALIGNMENT) {
        return None;
    }
    let section_alignment = match u32_le(data, optional.checked_add(32)?)? {
        0 => {
            fields.push(Field::SectionAlignment);
            DEFAULT_SECTION_ALIGNMENT
        }
        a if a.is_power_of_two() && a <= MAX_ALIGNMENT => a,
        _ => return None,
    };
    let file_alignment = match u32_le(data, optional.checked_add(36)?)? {
        0 => {
            fields.push(Field::FileAlignment);
            DEFAULT_FILE_ALIGNMENT.min(section_alignment)
        }
        a if a.is_power_of_two() && a <= section_alignment => a,
        _ => return None,
    };
    let entry = u32_at(optional.checked_add(16)?)?;
    let image_size = u32_at(optional.checked_add(56)?)?;
    let headers_size = u32_at(optional.checked_add(60)?)?;
    if image_size == 0 {
        return None;
    }
    let count_at = optional.checked_add(layout.directory_count_offset())?;
    let directories = match u32_le(data, count_at)? {
        0 => {
            fields.push(Field::DataDirectoryCount);
            DIRECTORY_ENTRIES
        }
        n if n <= DIRECTORY_ENTRIES => n,
        _ => return None,
    };

    let table = optional.checked_add(usize::from(layout.optional_header_size()))?;
    let table_end = table.checked_add(sections.checked_mul(SECTION_HEADER)?)?;
    let file_len = u64::try_from(data.len()).ok()?;
    let table_end_u64 = u64::try_from(table_end).ok()?;
    if headers_size != 0 && (headers_size < table_end_u64 || headers_size > file_len) {
        return None;
    }
    let (headers, _) = data.get(table..table_end)?.as_chunks::<SECTION_HEADER>();
    let (mut previous_address, mut previous_end) = (0u64, 0u64);
    let mut stored = false;
    let mut entry_in_section = false;
    for section in headers {
        let field = |at: usize| u32_le(section, at).map(u64::from);
        let (virtual_size, virtual_address) = (field(8)?, field(12)?);
        let (raw_size, raw_pointer) = (field(16)?, field(20)?);
        // The loader maps `SizeOfRawData` when `VirtualSize` is zero. A
        // wiper may zero `VirtualSize` too, leaving an uninitialized-data
        // section no extent at all: only its address then says where it is.
        let span = if virtual_size == 0 {
            raw_size
        } else {
            virtual_size
        };
        let end = virtual_address.checked_add(span)?;
        if virtual_address <= previous_address
            || !virtual_address.is_multiple_of(u64::from(section_alignment))
            || virtual_address < previous_end
            || end > image_size
        {
            return None;
        }
        (previous_address, previous_end) = (virtual_address, end);
        if raw_size != 0 {
            if !raw_pointer.is_multiple_of(u64::from(file_alignment))
                || raw_pointer < table_end_u64
                || raw_pointer.checked_add(raw_size)? > file_len
            {
                return None;
            }
            stored = true;
        }
        entry_in_section |= (virtual_address..end).contains(&entry);
    }
    if !stored || (entry != 0 && !entry_in_section) {
        return None;
    }

    let first_directory = count_at.checked_add(4)?;
    for index in (0..directories).filter(|&i| i != SECURITY_DIRECTORY) {
        let at = first_directory.checked_add(usize::try_from(index).ok()?.checked_mul(8)?)?;
        let (rva, size) = (u32_at(at)?, u32_at(at.checked_add(4)?)?);
        if size != 0 && (rva == 0 || rva.checked_add(size)? > image_size) {
            return None;
        }
    }

    Some(Header {
        nt_offset: nt,
        layout,
        section_alignment,
        file_alignment,
        fields,
    })
}

#[cfg(test)]
mod tests;
