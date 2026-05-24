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

use gimli::{
    DebugAbbrev, DebugInfo, DebugLineStr, DebugStr, DwLang, EndianSlice, LittleEndian, Reader,
};
use goblin::elf::Elf;
use serde_json::Value as JsonValue;
use std::collections::BTreeSet;

use crate::output::{Metrics, Values};

/// Maximum source-file names to retain. Real binaries can have
/// thousands of CUs (one per .o); we just need enough for attribution.
const MAX_SOURCE_FILES: usize = 32;

/// Walk the `.debug_info` compilation units and emit `elf.dwarf.*`
/// values. No-op when the section is absent (stripped binaries) or
/// when the ELF is big-endian — gimli's `RunTimeEndian` would require
/// templating the entire walk; BE ELFs are rare enough to punt.
pub(super) fn emit(elf: &Elf<'_>, bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    let Some(debug_info_data) = read_section(elf, bytes, ".debug_info") else {
        return;
    };
    let debug_abbrev_data = read_section(elf, bytes, ".debug_abbrev").unwrap_or(&[]);
    let debug_str_data = read_section(elf, bytes, ".debug_str").unwrap_or(&[]);
    let debug_line_str_data = read_section(elf, bytes, ".debug_line_str").unwrap_or(&[]);

    // ELF e_ident[EI_DATA]: 1 = little, 2 = big.
    if bytes.len() < 6 || bytes[5] != 1 {
        return;
    }
    let endian = LittleEndian;
    let debug_info = DebugInfo::new(debug_info_data, endian);
    let debug_abbrev = DebugAbbrev::new(debug_abbrev_data, endian);
    let debug_str = DebugStr::new(debug_str_data, endian);
    let debug_line_str = DebugLineStr::from(EndianSlice::new(debug_line_str_data, endian));

    let mut producers = BTreeSet::new();
    let mut comp_dirs = BTreeSet::new();
    let mut languages = BTreeSet::new();
    let mut source_files: Vec<String> = Vec::new();
    let mut cu_count: u32 = 0;

    let mut units = debug_info.units();
    while let Ok(Some(header)) = units.next() {
        cu_count = cu_count.saturating_add(1);
        let Ok(abbrevs) = header.abbreviations(&debug_abbrev) else {
            continue;
        };
        let mut entries = header.entries(&abbrevs);
        let Ok(Some((_, root))) = entries.next_dfs() else {
            continue;
        };
        let mut cu_name: Option<String> = None;
        let mut cu_comp_dir: Option<String> = None;

        let mut attrs = root.attrs();
        while let Ok(Some(attr)) = attrs.next() {
            match attr.name() {
                gimli::DW_AT_producer => {
                    if let Some(s) = attr_string(&attr, &debug_str, &debug_line_str) {
                        producers.insert(s);
                    }
                }
                gimli::DW_AT_comp_dir => {
                    if let Some(s) = attr_string(&attr, &debug_str, &debug_line_str) {
                        cu_comp_dir = Some(s.clone());
                        comp_dirs.insert(s);
                    }
                }
                gimli::DW_AT_name => {
                    if let Some(s) = attr_string(&attr, &debug_str, &debug_line_str) {
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
        values.insert(
            "elf.dwarf.producers",
            JsonValue::Array(producers.into_iter().map(JsonValue::String).collect()),
        );
    }
    if !comp_dirs.is_empty() {
        values.insert(
            "elf.dwarf.comp_dirs",
            JsonValue::Array(comp_dirs.into_iter().map(JsonValue::String).collect()),
        );
    }
    if !languages.is_empty() {
        values.insert(
            "elf.dwarf.languages",
            JsonValue::Array(languages.into_iter().map(JsonValue::String).collect()),
        );
    }
    if !source_files.is_empty() {
        values.insert(
            "elf.dwarf.source_files",
            JsonValue::Array(source_files.into_iter().map(JsonValue::String).collect()),
        );
    }
    if cu_count > 0 {
        metrics.insert("elf.dwarf.cu_count", f64::from(cu_count));
    }
}

fn read_section<'a>(elf: &Elf<'_>, bytes: &'a [u8], name: &str) -> Option<&'a [u8]> {
    let sh = elf
        .section_headers
        .iter()
        .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(name))?;
    let start = usize::try_from(sh.sh_offset).ok()?;
    let len = usize::try_from(sh.sh_size).ok()?;
    let end = start.checked_add(len)?;
    if end > bytes.len() {
        return None;
    }
    Some(&bytes[start..end])
}

fn attr_string<R: Reader>(
    attr: &gimli::Attribute<R>,
    debug_str: &DebugStr<R>,
    debug_line_str: &DebugLineStr<R>,
) -> Option<String> {
    match attr.value() {
        gimli::AttributeValue::String(s) => {
            s.to_string_lossy().ok().map(std::borrow::Cow::into_owned)
        }
        gimli::AttributeValue::DebugStrRef(off) => debug_str
            .get_str(off)
            .ok()
            .and_then(|r| r.to_string_lossy().ok().map(std::borrow::Cow::into_owned)),
        gimli::AttributeValue::DebugLineStrRef(off) => debug_line_str
            .get_str(off)
            .ok()
            .and_then(|r| r.to_string_lossy().ok().map(std::borrow::Cow::into_owned)),
        _ => None,
    }
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
}
