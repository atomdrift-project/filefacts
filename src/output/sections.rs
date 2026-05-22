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
//! - `flags` as a free-form, format-conventional string array.

use serde::Serialize;

/// One section / segment entry.
///
/// Carries the structural facts the format itself records plus
/// byte-level features computed from the section's bytes (Shannon
/// entropy). Optional fields are absent when the value is undefined
/// for this format or when the section has no on-disk bytes.
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

/// Unified section view across PE, ELF, and Mach-O.
///
/// Empty when the file has no section table filefacts can read
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

#[cfg(test)]
mod tests {
    use super::*;

    fn pe_text(vaddr: u64) -> Section {
        Section {
            name: ".text".into(),
            vaddr,
            vsize: 0x1000,
            file_offset: 0x400,
            file_size: 0x1000,
            flags: vec!["code".into(), "executable".into(), "readable".into()],
            flags_raw: Some(0x6000_0020),
            entropy: Some(6.10),
        }
    }

    #[test]
    fn empty_sections_default_is_zero_length() {
        let s = Sections::new();
        assert_eq!(s.len(), 0);
        assert!(s.is_empty());
        assert!(s.as_slice().is_empty());
        assert_eq!(s.iter().count(), 0);
    }

    /// `from_iter_sections` preserves the iterator order — the format
    /// extractors emit sections in load-table order, and aggregate
    /// metrics (size-weighted code/data entropy) depend on that order
    /// matching the layout.
    #[test]
    fn from_iter_preserves_insertion_order() {
        let mut a = pe_text(0x1000);
        a.name = ".text".into();
        let mut b = pe_text(0x2000);
        b.name = ".data".into();
        let mut c = pe_text(0x3000);
        c.name = ".rsrc".into();
        let sections = Sections::from_iter_sections([a, b, c]);
        let names: Vec<&str> = sections.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec![".text", ".data", ".rsrc"]);
    }

    /// Both `iter()` and `IntoIterator for &Sections` must walk the
    /// same elements in the same order. Several call sites in the
    /// PE/ELF/Mach-O analyzers use `&sections` inside `for` loops
    /// (which expands to the `IntoIterator` impl).
    #[test]
    fn iter_and_into_iter_agree() {
        let sections = Sections::from_iter_sections([pe_text(0x1000), pe_text(0x2000)]);
        let via_iter: Vec<u64> = sections.iter().map(|s| s.vaddr).collect();
        let via_into: Vec<u64> = (&sections).into_iter().map(|s| s.vaddr).collect();
        assert_eq!(via_iter, via_into);
    }

    /// Section flags survive a JSON round-trip — they're the
    /// load-bearing field for trait composites that match
    /// `flags[*] contains "executable"`. Order should match insertion
    /// so traits authoring against `flags[0]` get a stable position.
    #[test]
    fn json_round_trip_preserves_section_fields() {
        let sections = Sections::from_iter_sections([pe_text(0x1000)]);
        let json = serde_json::to_value(&sections).unwrap();
        let arr = json
            .as_array()
            .expect("Sections is `#[serde(transparent)]` Vec");
        assert_eq!(arr.len(), 1);
        let s = &arr[0];
        assert_eq!(s["name"], ".text");
        assert_eq!(s["vaddr"], 0x1000);
        assert_eq!(s["vsize"], 0x1000);
        assert_eq!(s["file_offset"], 0x400);
        assert_eq!(s["file_size"], 0x1000);
        let flags: Vec<&str> = s["flags"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(flags, vec!["code", "executable", "readable"]);
        assert_eq!(s["flags_raw"], 0x6000_0020_u64);
        assert!((s["entropy"].as_f64().unwrap() - 6.10).abs() < 1e-9);
    }

    /// `#[serde(transparent)]` means the wrapper struct doesn't add
    /// nesting — `Sections([...])` serializes as the bare array
    /// `[{...}]`. This is what kv-path consumers expect when they
    /// navigate `sections[0].name`.
    #[test]
    fn sections_serializes_as_bare_array_not_wrapped_object() {
        let sections = Sections::from_iter_sections([pe_text(0x1000)]);
        let json = serde_json::to_value(&sections).unwrap();
        assert!(
            json.is_array(),
            "Sections must serialize as an array, got {json}",
        );
    }
}
