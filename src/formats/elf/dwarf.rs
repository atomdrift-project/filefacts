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
//!
//! Sections are read in the file's byte order, and compressed ones
//! (`SHF_COMPRESSED` with zlib or zstd, or GNU `.zdebug_*`) are inflated
//! first, up to [`MAX_DECOMPRESSED_SECTION`] bytes each.

use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap};
use std::io::Read;

use gimli::{DebugAbbrev, DebugAbbrevOffset, DebugInfo, DwLang, RunTimeEndian};
use goblin::elf::Elf;
use goblin::elf::section_header::SHF_COMPRESSED;
use serde_json::Value as JsonValue;

use super::{section_bytes, section_header};
use crate::metric;
use crate::output::{Errors, Metrics, Values};
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

/// Bytes one compressed `.debug_*` section inflates to at most. The unit walk
/// reads only each unit's root DIE, so a prefix of a larger `.debug_info`
/// still yields the units it holds; the declared size of a compressed section
/// is the file's claim, and a few bytes of zlib can claim gigabytes.
const MAX_DECOMPRESSED_SECTION: usize = 32 << 20;

/// `Elf_Chdr.ch_type` values (`ELFCOMPRESS_*`).
const ELFCOMPRESS_ZLIB: u32 = 1;
const ELFCOMPRESS_ZSTD: u32 = 2;

/// Walk the `.debug_info` compilation units and emit `elf.dwarf.*`
/// values. No-op when the section is absent (stripped binaries).
pub(super) fn emit(
    elf: &Elf<'_>,
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    errors: &mut Errors,
) {
    let mut read = |name| debug_section(elf, bytes, name, errors).unwrap_or_default();
    let info = read("info");
    if info.is_empty() {
        return;
    }
    let sections = DwarfSections {
        endian: if elf.little_endian {
            RunTimeEndian::Little
        } else {
            RunTimeEndian::Big
        },
        info: &info,
        abbrev: &read("abbrev"),
        str: &read("str"),
        line_str: &read("line_str"),
    };
    emit_units(&sections, values, metrics);
}

/// The contents of `.debug_<name>`: the section's own bytes, or inflated
/// when it is `SHF_COMPRESSED` or stored as a GNU `.zdebug_<name>`. `None`
/// when there is no such section or it cannot be read.
fn debug_section<'a>(
    elf: &Elf<'_>,
    bytes: &'a [u8],
    name: &str,
    errors: &mut Errors,
) -> Option<Cow<'a, [u8]>> {
    let section = format!(".debug_{name}");
    if let Some(sh) = section_header(elf, &section) {
        let raw = section_bytes(sh, bytes)?;
        if sh.sh_flags & u64::from(SHF_COMPRESSED) == 0 {
            return Some(Cow::Borrowed(raw));
        }
        // `Elf32_Chdr` is `ch_type, ch_size, ch_addralign` as u32s;
        // `Elf64_Chdr` is `ch_type, ch_reserved` u32s, then u64s.
        let u32_at = |at| {
            if elf.little_endian {
                crate::bytes::u32_le(raw, at)
            } else {
                crate::bytes::u32_be(raw, at)
            }
        };
        let u64_at = |at| {
            if elf.little_endian {
                crate::bytes::u64_le(raw, at)
            } else {
                crate::bytes::u64_be(raw, at)
            }
        };
        let (kind, size, stream) = if elf.is_64 {
            (u32_at(0)?, u64_at(8)?, raw.get(24..)?)
        } else {
            (u32_at(0)?, u64::from(u32_at(4)?), raw.get(12..)?)
        };
        return inflate(&section, kind, stream, size, errors).map(Cow::Owned);
    }
    // GNU's older form: `ZLIB`, the inflated size as a big-endian u64, then
    // a zlib stream.
    let section = format!(".zdebug_{name}");
    let raw = section_bytes(section_header(elf, &section)?, bytes)?;
    let size = raw
        .strip_prefix(b"ZLIB")
        .and_then(|r| crate::bytes::u64_be(r, 0))?;
    inflate(&section, ELFCOMPRESS_ZLIB, raw.get(12..)?, size, errors).map(Cow::Owned)
}

/// Inflate the compressed contents of `section`, at most
/// [`MAX_DECOMPRESSED_SECTION`] bytes of the `declared` size. A stream that
/// fails to decode is recorded in `errors`; an unknown compression is skipped.
fn inflate(
    section: &str,
    kind: u32,
    stream: &[u8],
    declared: u64,
    errors: &mut Errors,
) -> Option<Vec<u8>> {
    let cap = crate::bytes::sat_usize(declared).min(MAX_DECOMPRESSED_SECTION);
    let mut out = Vec::new();
    let read = match kind {
        ELFCOMPRESS_ZLIB => flate2::read::ZlibDecoder::new(stream)
            .take(cap as u64)
            .read_to_end(&mut out),
        ELFCOMPRESS_ZSTD => zstd::stream::read::Decoder::new(stream).and_then(|mut decoder| {
            // The window the frame may demand is bounded like the output.
            decoder.window_log_max(MAX_DECOMPRESSED_SECTION.ilog2())?;
            decoder.take(cap as u64).read_to_end(&mut out)
        }),
        _ => {
            tracing::debug!(
                target: "filefacts::elf",
                stage = "dwarf",
                section,
                ch_type = kind,
                "compressed debug section uses an unknown compression; skipped"
            );
            return None;
        }
    };
    if let Err(error) = read {
        errors.record_malformed(
            crate::Stage::ElfParse,
            format!("{section}: compressed contents do not decode: {error}"),
        );
        return None;
    }
    if declared > cap as u64 {
        tracing::debug!(
            target: "filefacts::elf",
            stage = "dwarf",
            section,
            declared,
            len = out.len(),
            "compressed debug section inflated only up to the cap"
        );
    }
    Some(out)
}

/// The DWARF sections the unit walk reads, in the file's byte order.
struct DwarfSections<'a> {
    endian: RunTimeEndian,
    info: &'a [u8],
    abbrev: &'a [u8],
    str: &'a [u8],
    line_str: &'a [u8],
}

fn emit_units(sections: &DwarfSections<'_>, values: &mut Values, metrics: &mut Metrics) {
    let debug_info = DebugInfo::new(sections.info, sections.endian);

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
            DebugAbbrev::new(table, sections.endian)
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
    attr: &gimli::Attribute<gimli::EndianSlice<'_, RunTimeEndian>>,
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
mod tests;
