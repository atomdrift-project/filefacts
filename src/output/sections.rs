//! Section / segment table — unified across PE, ELF, and Mach-O.
//!
//! Every binary format describes its address space with a sequence of
//! named, sized regions: PE *sections*, ELF *sections*, Mach-O
//! *sections* (and segments). They share the same forensic surface,
//! so `expose` collapses them into a single uniform listing and
//! lets the consumer branch on [`crate::FileId`] when the
//! format-specific flag vocabulary matters.
//!
//! The forensically load-bearing field is **per-section entropy**:
//! packed and encrypted regions read out at ~8.0 bits/byte while
//! normal code sits around 5–6.5. Together with the executable /
//! writable flags this is enough to spot UPX, custom packers, and
//! encrypted payload blobs without parsing them further.
//!
//! Naming convention follows what radare2, `llvm-readobj`, and Ghidra
//! use:
//! - `vaddr` / `vsize` for virtual address and virtual size,
//! - `file_offset` / `file_size` for the on-disk extent,
//! - `flags` as a free-form, format-conventional string array.

use serde::Serialize;

/// One section / segment entry.
///
/// Carries only structural facts the format itself records. Numeric
/// features computed from the section's bytes (Shannon entropy,
/// for one) live in [`crate::Metrics`] under keys that mirror the
/// section's position (`sections[N].entropy`).
#[derive(Debug, Clone, Serialize)]
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
    /// Format-conventional flag names. PE: `code`, `initialized_data`,
    /// `uninitialized_data`, `executable`, `readable`, `writable`,
    /// `discardable`. ELF: `alloc`, `write`, `execinstr`, `merge`,
    /// `strings`, `info_link`, `tls`. Mach-O: `executable`,
    /// `readable`, `writable` distilled from the segment `initprot`.
    pub flags: Vec<String>,
}

/// Unified section view across PE, ELF, and Mach-O.
///
/// Empty when the file has no section table expose can read
/// (structured documents, source code, opaque blobs).
#[derive(Debug, Clone, Default, Serialize)]
#[serde(transparent)]
pub struct Sections(Vec<Section>);

impl Sections {
    /// Empty section table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from an iterator of [`Section`]s.
    pub(crate) fn from_iter_sections(iter: impl IntoIterator<Item = Section>) -> Self {
        Self(iter.into_iter().collect())
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
