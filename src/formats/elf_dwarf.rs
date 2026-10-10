//! DWARF compilation-unit metadata extraction for unstripped ELF
//! binaries. Surfaces the per-CU attributes that carry the richest
//! build-environment attribution available in any binary format:
//!
//! - **DW_AT_producer** — full compile command line, e.g.
//!   `"GNU C17 13.2.0 -mtune=generic -march=x86-64 -O2 -fstack-protector-strong"`.
//!   Distinguishes Ubuntu/Debian/Wolfi/Chainguard GCC builds, MSVC,
//!   clang versions, Rust, Go's `gccgo`, etc.
//! - **DW_AT_comp_dir** — build directory at compile time, e.g.
//!   `"/builddir/build/BUILD/glibc-2.34/build-x86_64-linux"`.
//!   Leaks the build host's filesystem layout — distros use
//!   distinctive build-root patterns (Debian: `/build/<pkg>-*`,
//!   Fedora: `/builddir/build/BUILD/`, Wolfi: `/home/build/`,
//!   Yocto: `/work/<arch>/`).
//! - **DW_AT_name** — main source filename per CU, capped per file.
//! - **DW_AT_language** — source language (C, C++, Rust, Go, etc).
//!
//! Stripped binaries have no `.debug_*` sections and the extractor
//! emits nothing. Most malware is stripped, so this is primarily an
//! attribution surface for legitimate vendor binaries — exactly what
//! supply-chain swap detection needs.

use crate::metric;
use gimli::{DebugAbbrev, DebugAbbrevOffset, DebugInfo, DwLang, LittleEndian};
use goblin::elf::Elf;
use serde_json::Value as JsonValue;
use std::collections::{BTreeSet, HashMap};

use super::elf::read_section;
use crate::output::{Metrics, Values};
use crate::value_key;

/// Maximum source-file names to retain. Real binaries can have
/// thousands of CUs (one per .o); we just need enough for attribution.
const MAX_SOURCE_FILES: usize = 32;

/// Distinct producers, and distinct build directories, retained. A real
/// binary has a handful of each; every unit can name a different one.
const MAX_DISTINCT_STRINGS: usize = 1024;

/// Longest string attribute read, in bytes. A `.debug_str` reference is an
/// offset into one shared table, so every unit can name the same NUL-less
/// megabyte; reading it whole per unit is `units × run` work. Real producer
/// command lines and paths are well under this.
const MAX_ATTR_STRING: usize = 16 * 1024;

/// Root-DIE attributes read per unit. A real compile-unit DIE carries about
/// a dozen. One abbreviation can declare thousands of zero-width
/// (`DW_FORM_flag_present`) attributes that every unit's root then shares.
const MAX_ROOT_ATTRS: usize = 256;

/// Walk the `.debug_info` compilation units and emit `elf.dwarf.*`
/// values. No-op when the section is absent (stripped binaries) or
/// when the ELF is big-endian — gimli's `RunTimeEndian` would require
/// templating the entire walk; BE ELFs are rare enough to punt.
pub(super) fn emit(elf: &Elf<'_>, bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    let Some(debug_info) = read_section(elf, bytes, ".debug_info") else {
        return;
    };
    // ELF e_ident[EI_DATA]: 1 = little, 2 = big.
    if bytes.get(5) != Some(&1) {
        return;
    }
    let sections = DwarfSections {
        info: debug_info,
        abbrev: read_section(elf, bytes, ".debug_abbrev").unwrap_or(&[]),
        str: read_section(elf, bytes, ".debug_str").unwrap_or(&[]),
        line_str: read_section(elf, bytes, ".debug_line_str").unwrap_or(&[]),
    };
    emit_units(&sections, values, metrics);
}

/// The little-endian DWARF sections the unit walk reads.
struct DwarfSections<'a> {
    info: &'a [u8],
    abbrev: &'a [u8],
    str: &'a [u8],
    line_str: &'a [u8],
}

fn emit_units(sections: &DwarfSections<'_>, values: &mut Values, metrics: &mut Metrics) {
    let debug_info = DebugInfo::new(sections.info, LittleEndian);

    // Each unit names its abbreviation table by offset, and gimli parses a
    // table up to its NUL code or the end of the section. Units are
    // file-controlled and as small as 11 bytes, so a fresh parse per unit,
    // or of a table at every offset into one terminator-less run, is
    // `units × table` work. Parse each distinct offset once, from a slice
    // ending at the next unit's table: an honest table is terminated before
    // the next one starts, so it parses the same.
    let mut table_starts = Vec::new();
    let mut units = debug_info.units();
    while let Ok(Some(header)) = units.next() {
        table_starts.push(header.debug_abbrev_offset().0);
    }
    table_starts.sort_unstable();
    table_starts.dedup();
    let mut tables = HashMap::new();

    let mut producers = BTreeSet::new();
    let mut comp_dirs = BTreeSet::new();
    let mut languages = BTreeSet::new();
    let mut source_files: Vec<String> = Vec::new();
    let mut cu_count: u32 = 0;

    let mut units = debug_info.units();
    while let Ok(Some(header)) = units.next() {
        cu_count = cu_count.saturating_add(1);
        let start = header.debug_abbrev_offset().0;
        let abbrevs = tables.entry(start).or_insert_with(|| {
            let end = table_starts
                .get(table_starts.partition_point(|&s| s <= start))
                .copied()
                .unwrap_or(sections.abbrev.len());
            let table = sections.abbrev.get(start..end)?;
            DebugAbbrev::new(table, LittleEndian)
                .abbreviations(DebugAbbrevOffset(0))
                .ok()
        });
        let Some(abbrevs) = abbrevs.as_ref() else {
            continue;
        };
        let mut entries = header.entries(abbrevs);
        let Ok(Some((_, root))) = entries.next_dfs() else {
            continue;
        };
        let mut cu_name: Option<String> = None;
        let mut cu_comp_dir: Option<String> = None;

        let mut attrs = root.attrs();
        let mut read = 0;
        while read < MAX_ROOT_ATTRS
            && let Ok(Some(attr)) = attrs.next()
        {
            read += 1;
            match attr.name() {
                gimli::DW_AT_producer => {
                    if let Some(s) = attr_string(&attr, sections) {
                        insert_capped(&mut producers, s);
                    }
                }
                gimli::DW_AT_comp_dir => {
                    if let Some(s) = attr_string(&attr, sections) {
                        cu_comp_dir = Some(s.clone());
                        insert_capped(&mut comp_dirs, s);
                    }
                }
                gimli::DW_AT_name => {
                    if let Some(s) = attr_string(&attr, sections) {
                        cu_name = Some(s);
                    }
                }
                gimli::DW_AT_language => {
                    if let gimli::AttributeValue::Language(lang) = attr.value() {
                        languages.insert(language_name(lang).to_string());
                    }
                }
                _ => {}
            }
        }

        if let Some(name) = cu_name {
            if source_files.len() < MAX_SOURCE_FILES {
                let full = match cu_comp_dir.as_deref() {
                    Some(dir) if !name.starts_with('/') => format!("{}/{}", dir, name),
                    _ => name,
                };
                if !source_files.contains(&full) {
                    source_files.push(full);
                }
            }
        }
    }

    if !producers.is_empty() {
        values.insert_key(
            value_key!("elf.dwarf.producers"),
            JsonValue::Array(producers.into_iter().map(JsonValue::String).collect()),
        );
    }
    if !comp_dirs.is_empty() {
        values.insert_key(
            value_key!("elf.dwarf.comp_dirs"),
            JsonValue::Array(comp_dirs.into_iter().map(JsonValue::String).collect()),
        );
    }
    if !languages.is_empty() {
        values.insert_key(
            value_key!("elf.dwarf.languages"),
            JsonValue::Array(languages.into_iter().map(JsonValue::String).collect()),
        );
    }
    if !source_files.is_empty() {
        values.insert_key(
            value_key!("elf.dwarf.source_files"),
            JsonValue::Array(source_files.into_iter().map(JsonValue::String).collect()),
        );
    }
    if cu_count > 0 {
        metrics.insert(metric!("elf.dwarf.cu_count"), f64::from(cu_count));
    }
}

/// Add `s` unless the set already holds [`MAX_DISTINCT_STRINGS`] others.
fn insert_capped(set: &mut BTreeSet<String>, s: String) {
    if set.len() < MAX_DISTINCT_STRINGS || set.contains(&s) {
        set.insert(s);
    }
}

/// A string-valued attribute: inline, or a NUL-terminated entry of
/// `.debug_str` / `.debug_line_str`, read no further than
/// [`MAX_ATTR_STRING`] bytes.
fn attr_string(
    attr: &gimli::Attribute<gimli::EndianSlice<'_, LittleEndian>>,
    sections: &DwarfSections<'_>,
) -> Option<String> {
    let bytes = match attr.value() {
        gimli::AttributeValue::String(s) => s.slice(),
        gimli::AttributeValue::DebugStrRef(off) => sections.str.get(off.0..)?,
        gimli::AttributeValue::DebugLineStrRef(off) => sections.line_str.get(off.0..)?,
        _ => return None,
    };
    let window = bytes.get(..MAX_ATTR_STRING).unwrap_or(bytes);
    let s = window.split(|&b| b == 0).next()?;
    Some(String::from_utf8_lossy(s).into_owned())
}

/// Map a DW_LANG_* constant to a human-readable canonical name.
fn language_name(lang: DwLang) -> &'static str {
    match lang {
        gimli::DW_LANG_C
        | gimli::DW_LANG_C89
        | gimli::DW_LANG_C99
        | gimli::DW_LANG_C11
        | gimli::DW_LANG_C17 => "c",
        gimli::DW_LANG_C_plus_plus
        | gimli::DW_LANG_C_plus_plus_03
        | gimli::DW_LANG_C_plus_plus_11
        | gimli::DW_LANG_C_plus_plus_14 => "cpp",
        gimli::DW_LANG_Rust => "rust",
        gimli::DW_LANG_Go => "go",
        gimli::DW_LANG_Swift => "swift",
        gimli::DW_LANG_ObjC => "objc",
        gimli::DW_LANG_ObjC_plus_plus => "objcpp",
        gimli::DW_LANG_Fortran77
        | gimli::DW_LANG_Fortran90
        | gimli::DW_LANG_Fortran95
        | gimli::DW_LANG_Fortran03
        | gimli::DW_LANG_Fortran08 => "fortran",
        gimli::DW_LANG_Ada83 | gimli::DW_LANG_Ada95 => "ada",
        gimli::DW_LANG_Haskell => "haskell",
        gimli::DW_LANG_OCaml => "ocaml",
        gimli::DW_LANG_Mips_Assembler => "asm",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_name_known_constants() {
        assert_eq!(language_name(gimli::DW_LANG_C99), "c");
        assert_eq!(language_name(gimli::DW_LANG_Rust), "rust");
        assert_eq!(language_name(gimli::DW_LANG_Go), "go");
        assert_eq!(language_name(gimli::DW_LANG_C_plus_plus_14), "cpp");
    }

    #[test]
    fn language_name_unknown_falls_through() {
        assert_eq!(language_name(DwLang(0xC000)), "unknown");
    }

    /// Units all share one abbreviation whose root declares 50 000
    /// zero-width attributes after a `.debug_str` producer that runs 64 KiB
    /// without a NUL. Re-parsing the table, walking every attribute and
    /// scanning the string per unit was `units × (table + run)`; each is now
    /// paid once or capped, and the facts survive.
    #[test]
    fn shared_abbreviation_and_string_cost_once_per_file() {
        const UNITS: usize = 5000;
        let mut abbrev = vec![1, 0x11, 0]; // code 1: DW_TAG_compile_unit, no children
        abbrev.extend([0x25, 0x0e]); // DW_AT_producer, DW_FORM_strp
        for _ in 0..50_000 {
            abbrev.extend([0x80, 0x40, 0x19]); // DW_AT 0x2000, DW_FORM_flag_present
        }
        abbrev.extend([0, 0, 0]);
        let mut info = Vec::new();
        for _ in 0..UNITS {
            info.extend(12u32.to_le_bytes()); // unit_length
            info.extend(4u16.to_le_bytes()); // DWARF 4
            info.extend(0u32.to_le_bytes()); // debug_abbrev_offset
            info.push(8); // address size
            info.push(1); // root DIE, abbreviation 1
            info.extend(0u32.to_le_bytes()); // DW_AT_producer strp
        }
        let strs = vec![b'p'; 64 * 1024];
        let sections = DwarfSections {
            info: &info,
            abbrev: &abbrev,
            str: &strs,
            line_str: &[],
        };
        let mut values = Values::new();
        let mut metrics = Metrics::default();
        emit_units(&sections, &mut values, &mut metrics);
        assert_eq!(metrics.get("elf.dwarf.cu_count"), Some(UNITS as f64));
        let producers = values
            .get("elf.dwarf.producers")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(producers.len(), 1);
        assert_eq!(producers[0].as_str().unwrap().len(), MAX_ATTR_STRING);
    }

    /// Each unit's table is parsed from a slice ending where the next unit's
    /// table starts, so units at successive offsets into one unterminated
    /// table do not each parse the rest of it; honest tables parse the same.
    #[test]
    fn abbreviation_tables_end_at_the_next_table() {
        // Table A at 0: code 1 = compile_unit with DW_AT_name/DW_FORM_string,
        // terminated. Table B follows: code 1 = compile_unit with
        // DW_AT_comp_dir/DW_FORM_string.
        let mut abbrev = vec![1, 0x11, 0, 0x03, 0x08, 0, 0, 0];
        let b_start = abbrev.len() as u32;
        abbrev.extend([1, 0x11, 0, 0x1b, 0x08, 0, 0, 0]);
        let mut info = Vec::new();
        for (table, text) in [(0, b"main.c\0"), (b_start, b"/build\0")] {
            info.extend((7 + text.len() as u32 + 1).to_le_bytes());
            info.extend(4u16.to_le_bytes());
            info.extend(table.to_le_bytes());
            info.push(8);
            info.push(1);
            info.extend_from_slice(text);
        }
        let sections = DwarfSections {
            info: &info,
            abbrev: &abbrev,
            str: &[],
            line_str: &[],
        };
        let mut values = Values::new();
        let mut metrics = Metrics::default();
        emit_units(&sections, &mut values, &mut metrics);
        assert_eq!(
            values.get("elf.dwarf.source_files"),
            Some(&serde_json::json!(["main.c"]))
        );
        assert_eq!(
            values.get("elf.dwarf.comp_dirs"),
            Some(&serde_json::json!(["/build"]))
        );
    }
}
