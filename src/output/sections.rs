//! Section / segment table — unified across PE, ELF, and Mach-O.
//!
//! Every binary format describes its address space with a sequence of
//! named, sized regions: PE *sections*, ELF *sections*, Mach-O
//! *sections* (and segments). They share the same forensic surface,
//! so `filefacts` collapses them into a single uniform listing and
//! lets the consumer branch on [`crate::FileId`] when the
//! format-specific flag vocabulary matters.
//!
//! The forensically load-bearing field is **per-section entropy**:
//! packed and encrypted regions read out at ~8.0 bits/byte while
//! normal code sits around 5–6.5. Together with the executable /
//! writable flags this is enough to spot UPX, custom packers, and
//! encrypted payload blobs without parsing them further. Entropy
//! lives on the [`Section`] itself, alongside the structural fields
//! it derives from.
//!
//! Naming convention follows what radare2, `llvm-readobj`, and Ghidra
//! use:
//! - `vaddr` / `vsize` for virtual address and virtual size,
//! - `file_offset` / `file_size` for the on-disk extent,
//! - `flags` as one [`SectionFlag`] vocabulary shared by every format.

use serde::{Deserialize, Serialize};

/// One section attribute, in a vocabulary shared by PE, ELF and Mach-O.
///
/// Each format's flags map onto it once, where the section is read, so a
/// consumer tests [`SectionFlag::Writable`] rather than every format's
/// spelling of it. Serialized as the snake_case name (`"executable"`,
/// `"initialized_data"`, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SectionFlag {
    /// Mapped readable (PE `IMAGE_SCN_MEM_READ`, Mach-O `VM_PROT_READ`).
    Readable,
    /// Mapped writable (PE `IMAGE_SCN_MEM_WRITE`, ELF `SHF_WRITE`, Mach-O
    /// `VM_PROT_WRITE`).
    Writable,
    /// Mapped executable (PE `IMAGE_SCN_MEM_EXECUTE`, ELF `SHF_EXECINSTR`,
    /// Mach-O `VM_PROT_EXECUTE`).
    Executable,
    /// Holds instructions (PE `IMAGE_SCN_CNT_CODE`; a Mach-O section with
    /// instruction attributes or symbol stubs).
    Code,
    /// A Mach-O section without instructions, even in an executable segment.
    Data,
    /// PE `IMAGE_SCN_CNT_INITIALIZED_DATA`.
    InitializedData,
    /// PE `IMAGE_SCN_CNT_UNINITIALIZED_DATA`.
    UninitializedData,
    /// ELF `SHF_ALLOC`: occupies memory at run time.
    Alloc,
    /// ELF `SHF_MERGE`.
    Merge,
    /// ELF `SHF_STRINGS`.
    Strings,
    /// ELF `SHF_INFO_LINK`.
    InfoLink,
    /// ELF `SHF_TLS`.
    Tls,
}

impl SectionFlag {
    /// The serialized name, e.g. `"executable"`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Readable => "readable",
            Self::Writable => "writable",
            Self::Executable => "executable",
            Self::Code => "code",
            Self::Data => "data",
            Self::InitializedData => "initialized_data",
            Self::UninitializedData => "uninitialized_data",
            Self::Alloc => "alloc",
            Self::Merge => "merge",
            Self::Strings => "strings",
            Self::InfoLink => "info_link",
            Self::Tls => "tls",
        }
    }
}

impl std::fmt::Display for SectionFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One section / segment entry.
///
/// Carries the structural facts the format itself records plus
/// byte-level features computed from the section's bytes (Shannon
/// entropy). Optional fields are absent when the value is undefined
/// for this format or when the section has no on-disk bytes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Section {
    /// Section name as the format records it (`.text`, `__TEXT,__text`,
    /// etc.). Empty when the format has no name for this region.
    pub name: String,
    /// Virtual address where the section is loaded.
    pub vaddr: u64,
    /// Size of the section when loaded into memory.
    pub vsize: u64,
    /// Offset of the section bytes within the file. `0` for purely
    /// virtual sections (BSS, ELF `nobits`).
    pub file_offset: u64,
    /// Size of the section bytes on disk. `0` when the section has no
    /// file-backed bytes.
    pub file_size: u64,
    /// Section attributes in the shared [`SectionFlag`] vocabulary. PE:
    /// `code`, `initialized_data`, `uninitialized_data`, `executable`,
    /// `readable`, `writable`. ELF: `writable`, `alloc`, `executable`,
    /// `merge`, `strings`, `info_link`, `tls`. Mach-O: `readable`,
    /// `writable`, `executable` from the segment `initprot`, plus `code` or
    /// `data` from the section's instruction attributes/type.
    pub flags: Vec<SectionFlag>,
    /// Raw format-specific flag bitmask backing [`Self::flags`]. PE:
    /// the `IMAGE_SCN_*` `characteristics` u32. ELF: the `sh_flags`
    /// u64. Mach-O: the section / segment `initprot`. `None` when the
    /// format has no single integer for flag state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags_raw: Option<u64>,
    /// Shannon entropy of the section's on-disk bytes, in
    /// bits per byte (range 0.0..=8.0). `None` for purely virtual
    /// sections with no file bytes (BSS, ELF `nobits`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy: Option<f64>,
}

impl Section {
    /// `true` when the section carries `flag`.
    pub fn has_flag(&self, flag: SectionFlag) -> bool {
        self.flags.contains(&flag)
    }

    /// `true` when the section is mapped executable.
    pub fn is_executable(&self) -> bool {
        self.has_flag(SectionFlag::Executable)
    }

    /// Instruction-bearing executable section. Mach-O data can share an
    /// executable segment with code; its explicit `data` flag excludes it.
    pub fn is_code(&self) -> bool {
        self.is_executable() && !self.has_flag(SectionFlag::Data)
    }

    /// `true` when the section is mapped writable.
    pub fn is_writable(&self) -> bool {
        self.has_flag(SectionFlag::Writable)
    }
}

/// Unified section view across PE, ELF, and Mach-O.
///
/// Empty when the file has no section table filefacts can read
/// (structured documents, source code, opaque blobs).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Sections(Vec<Section>);

impl Sections {
    /// Empty section table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrow the underlying section vector.
    pub fn as_slice(&self) -> &[Section] {
        &self.0
    }

    /// Iterate sections in insertion order (the order the format
    /// records them).
    pub fn iter(&self) -> std::slice::Iter<'_, Section> {
        self.0.iter()
    }

    /// Number of sections.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// `true` when the section table is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'a> IntoIterator for &'a Sections {
    type Item = &'a Section;
    type IntoIter = std::slice::Iter<'a, Section>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl FromIterator<Section> for Sections {
    fn from_iter<I: IntoIterator<Item = Section>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

#[cfg(test)]
mod tests;
