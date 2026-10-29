//! ELF extractor.
//!
//! Reads Linux executables, shared libraries, relocatable objects and core
//! dumps. Surfaces the file header, the program and section tables, the
//! dynamic section (DT_NEEDED, RPATH, SONAME, symbol versions, init arrays),
//! dynamic and static symbols, notes (GNU build-id, ABI tag, FDO package
//! metadata, GNU properties), `.comment` toolchain banners, DWARF compile-unit
//! attribution, direct syscall sites, Go build info and similarity hashes.

mod dwarf;
mod dynamic;
mod hashes;
mod metrics;
mod notes;
mod symbols;
mod syscalls;

use std::collections::BTreeSet;

use goblin::elf::{Elf, SectionHeader, header};
use serde_json::Value as JsonValue;

use crate::formats::common::{
    NativeFormat, RizinTarget, XorScan, extract_binary_strings, extract_binary_strings_from_object,
    put_str, put_u64, rizin_fallback, section_entropy,
};
use crate::formats::goblin_safe;
use crate::metric;
use crate::output::{Metrics, Section, SectionFlag, Values};
use crate::value_key;

/// Longest section name copied into the sections view, in chars.
const MAX_SECTION_NAME: usize = 256;

/// Version records (`Elf_Verdef` / `Elf_Verneed` and their aux entries) walked
/// per table. A real binary declares a few dozen. The walks follow
/// file-controlled `*_next` links with a 16-bit aux count per record, so every
/// need can share one long aux chain: `needs × aux` records from a few MB.
const MAX_VERSION_RECORDS: usize = 4096;

/// Bytes of string-table text one output view copies out of the file:
/// symbol, library and version names.
///
/// Those names are borrowed slices of a string table, and nothing stops every
/// record from naming the same NUL-less run, or each a suffix of it, so
/// copying them all costs `records × run length`, quadratic in the file
/// (64 KiB of dynsym over a 1 MiB run is 2.7 GiB of names). An honest table's
/// names are, but for a few repeats, disjoint slices of the file, so twice its
/// length never truncates one. Once a name does not fit, the view is spent:
/// every later name is refused too.
struct NameBudget {
    left: usize,
    refused: bool,
}

impl NameBudget {
    fn new(file_len: usize) -> Self {
        Self {
            left: file_len.saturating_mul(2),
            refused: false,
        }
    }

    /// Charge `len` bytes of name text; `false` once the view is spent.
    fn take(&mut self, len: usize) -> bool {
        match self.left.checked_sub(len) {
            Some(left) if !self.refused => {
                self.left = left;
                true
            }
            _ => {
                self.refused = true;
                false
            }
        }
    }

    /// Whether any name was refused.
    fn refused(&self) -> bool {
        self.refused
    }
}

/// File ranges `[start, end)` answering "does one of them contain this
/// range?" in `O(log n)`. Sections and program headers are both
/// file-controlled and up to `file length / 64` of each, so a pairwise test of
/// every section against every segment is quadratic in the file.
struct RangeCover {
    starts: Vec<u64>,
    /// `max_end[i]`: the furthest end among the ranges sorted at or before `i`.
    max_end: Vec<u64>,
}

impl RangeCover {
    fn new(mut ranges: Vec<(u64, u64)>) -> Self {
        ranges.sort_unstable();
        let mut furthest = 0;
        let max_end = ranges
            .iter()
            .map(|&(_, end)| {
                furthest = furthest.max(end);
                furthest
            })
            .collect();
        Self {
            starts: ranges.into_iter().map(|(start, _)| start).collect(),
            max_end,
        }
    }

    fn is_empty(&self) -> bool {
        self.starts.is_empty()
    }

    /// Whether a single range holds all of `[start, end)`: among the ranges
    /// starting at or before `start`, the one reaching furthest must reach
    /// `end`.
    fn contains(&self, start: u64, end: u64) -> bool {
        let before = self.starts.partition_point(|&s| s <= start);
        before
            .checked_sub(1)
            .and_then(|i| self.max_end.get(i))
            .is_some_and(|&furthest| furthest >= end)
    }
}

/// Indices of the ranges `[start, end, index)` that intersect at least one
/// other range.
///
/// The same running furthest-end sweep as [`RangeCover`], in start order: a
/// range intersects an earlier one exactly when it starts before the furthest
/// end seen so far, and the range reaching that end is one it intersects. A
/// range that intersects only later ranges reaches furthest when the first of
/// them arrives, so it is found then. Comparing sorted neighbours alone misses
/// `[0, 100)` against `[30, 40)` when `[10, 20)` sorts between them.
fn overlapping(mut ranges: Vec<(u64, u64, usize)>) -> BTreeSet<usize> {
    ranges.sort_unstable();
    let mut out = BTreeSet::new();
    let mut furthest: Option<(u64, usize)> = None;
    for (start, end, index) in ranges {
        if let Some((far_end, far_index)) = furthest
            && far_end > start
        {
            out.insert(far_index);
            out.insert(index);
        }
        if furthest.is_none_or(|(far_end, _)| end > far_end) {
            furthest = Some((end, index));
        }
    }
    out
}

pub(super) fn extract(bytes: &[u8], ctx: super::ExtractCtx<'_>) {
    let super::ExtractCtx {
        values,
        strings,
        metrics,
        sections: sections_out,
        symbols: symbols_out,
        errors: errors_out,
        image_end,
        ref rizin,
        ..
    } = ctx;
    // goblin's dynamic-section walker has panicked on malformed `DT_*`
    // tables; `parse_elf` turns a panic into an outcome. A failed parse is
    // recorded in `errors`, and the byte-level facts the generic pass already
    // put in `metrics` and `strings` stand.
    //
    // Owns the header-patched copy when the section header table was cut
    // off; declared here so the parse borrowing it outlives the match.
    let detached;
    let mut section_headers_truncated = false;
    let mut original_section_table = None;
    let elf = match goblin_safe::parse_elf(bytes) {
        goblin_safe::GoblinOutcome::Ok(elf) => elf,
        goblin_safe::GoblinOutcome::Failed(e) => {
            // A truncated file loses its trailing section header table first.
            // Parse the segment view instead of discarding the whole binary;
            // offsets are unchanged, so `bytes` stays authoritative below.
            detached = goblin_safe::elf_without_truncated_section_headers(bytes);
            errors_out.record_malformed(crate::Stage::ElfParse, e.to_string());
            if let Some(patched) = detached.as_ref()
                && let goblin_safe::GoblinOutcome::Ok(elf) = goblin_safe::parse_elf(&patched.bytes)
            {
                tracing::debug!(
                    target: "filefacts::elf",
                    stage = "parse",
                    error = %e,
                    "section header table runs past the file; parsing the segment view"
                );
                metrics.insert(metric!("elf.section_headers_truncated"), 1.0);
                section_headers_truncated = true;
                original_section_table = Some((patched.shoff, patched.shstrndx));
                elf
            } else {
                extract_binary_strings(bytes, strings, XorScan::Yes);
                metrics.insert(metric!("elf.parse_failed"), 1.0);
                return;
            }
        }
        goblin_safe::GoblinOutcome::Panicked(msg) => {
            extract_binary_strings(bytes, strings, XorScan::Yes);
            errors_out.record_panic(crate::Stage::ElfParse, msg);
            metrics.insert(metric!("elf.parse_panicked"), 1.0);
            return;
        }
    };

    // Reuse this parse for string extraction (move into an Object for stng,
    // then move back out) so the binary isn't parsed a second time.
    let object = goblin::Object::Elf(elf);
    extract_binary_strings_from_object(&object, bytes, strings, XorScan::Yes);
    let goblin::Object::Elf(elf) = object else {
        unreachable!("constructed as Object::Elf")
    };
    // Every PT_NOTE reader below shares one guarded walk.
    let segment_notes = notes::drain(elf.iter_note_headers(bytes), &mut bytes.len(), errors_out);

    elf_header(&elf, values);
    // The recovery parse zeroes these fields in its copy. Report the header's
    // own values rather than the synthetic ones.
    if let Some((shoff, shstrndx)) = original_section_table {
        put_u64(values, value_key!("elf.shoff"), shoff);
        put_u64(values, value_key!("elf.shstrndx"), shstrndx);
    }
    dynamic::names(&elf, bytes.len(), values);
    sections(&elf, bytes, sections_out);
    *image_end = Some(image_end_of(&elf));
    symbols::emit(&elf, bytes.len(), values, metrics, symbols_out);
    notes::build_id(&elf, bytes, &segment_notes, values, metrics, errors_out);
    if let Some(interp) = elf.interpreter {
        put_str(values, value_key!("elf.interpreter"), interp);
    }
    dynamic::relro(&elf, values);
    dynamic::needed_versions(&elf, bytes.len(), values, errors_out);
    dynamic::verdef(&elf, bytes.len(), values, errors_out);
    dynamic::init_arrays(&elf, bytes, values, metrics);
    dynamic::dynsym_funcs(&elf, bytes.len(), values);
    syscalls::emit(&elf, bytes, values, metrics);
    if !section_headers_truncated {
        metrics::absent_metadata(&elf, values, metrics);
    }
    comment(&elf, bytes, values, metrics);
    gcc_command_line(&elf, bytes, values);
    dwarf::emit(&elf, bytes, values, metrics, errors_out);
    dynamic::dt_flags(&elf, values);
    notes::abi_tag(&segment_notes, values);
    notes::package(&segment_notes, values);
    notes::gnu_property(&elf, &segment_notes, values, metrics);
    metrics::binary_flags(&elf, section_headers_truncated, metrics);
    metrics::header_and_layout(&elf, &segment_notes, metrics, values);
    dynamic::tag_metrics(&elf, bytes.len(), metrics);
    metrics::table_counts(&elf, metrics);
    dynamic::relocation_kinds(&elf, values);
    segments(&elf, values);
    section_headers(&elf, values);
    notes::segment_coverage(&elf, bytes, metrics, errors_out);
    metrics::section_file_anomalies(&elf, bytes, metrics);
    metrics::member_layout(&elf, bytes.len(), metrics);
    // Split firmware header members declare segments stored in sibling files.
    // Disassembling such a member invents an entry function in an unmapped
    // range. Keep its header facts, but recover code only from present bytes.
    if has_present_load_or_code_bytes(&elf, bytes.len()) {
        rizin_fallback(
            RizinTarget {
                format: NativeFormat::Elf,
                bytes,
                strings,
                // A real pclntab magic, not just the section name: no non-Go
                // toolchain writes one, so a decoy `.gopclntab` cannot skip
                // deep recovery for a stripped payload.
                go_function_metadata: read_section(&elf, bytes, ".gopclntab")
                    .is_some_and(super::go_buildinfo::has_pclntab_magic),
                settings: rizin,
            },
            sections_out,
            symbols_out,
            metrics,
        );
    }
    // Preserve symbol-table function names when no disassembler supplied
    // functions. Run after the fallback so symbol-table names never suppress
    // richer Rizin function and call-graph facts.
    symbols::static_function_fallback(&elf, bytes.len(), symbols_out);
    linker_family(&elf, values);
    comment_fingerprint(values);
    hashes::emit(&elf, bytes.len(), values, symbols_out);
    super::upx::detect(bytes, values);
    let go_sections = super::go_buildinfo::GoSections {
        buildinfo: go_buildinfo_region(&elf, bytes),
        buildid_note: read_section(&elf, bytes, ".note.go.buildid"),
        pclntab: read_section(&elf, bytes, ".gopclntab"),
        rodata: read_section(&elf, bytes, ".rodata"),
    };
    // The pre-1.18 build-info layout stores pointers, not inline strings.
    let resolve =
        |va| load_segment_va_to_offset(&elf, va).and_then(|off| usize::try_from(off).ok());
    super::go_buildinfo::detect(
        bytes,
        values,
        value_key!("elf.go"),
        Some(&resolve),
        &go_sections,
    );
    super::build_toolchain::from_elf(values, sections_out, bytes);
}

/// Where Go's `debug/buildinfo` reads the build-info blob from: the
/// `.go.buildinfo` section, else the first writable, non-executable `PT_LOAD`
/// segment, whose start the linker places it near when there is no section
/// table.
fn go_buildinfo_region<'a>(elf: &Elf<'_>, bytes: &'a [u8]) -> Option<&'a [u8]> {
    use goblin::elf::program_header::{PF_W, PF_X, PT_LOAD};
    if let Some(sh) = section_header(elf, ".go.buildinfo") {
        return section_bytes(sh, bytes);
    }
    let ph = elf
        .program_headers
        .iter()
        .find(|p| p.p_type == PT_LOAD && p.p_flags & (PF_X | PF_W) == PF_W)?;
    let start = usize::try_from(ph.p_offset).ok()?;
    let len = usize::try_from(ph.p_filesz).ok()?;
    bytes.get(start..start.checked_add(len)?.min(bytes.len()))
}

/// Identify the linker family that produced this binary. Prefers the
/// dedicated `.note.*` sections (canonical, written by the linker
/// itself); falls back to scanning `.comment[]` banners for the
/// linker's name. Emits a single `elf.linker_family` string.
fn linker_family(elf: &Elf<'_>, values: &mut Values) {
    let by_section = |name| section_header(elf, name).is_some();
    let family = if by_section(".note.gnu.gold-version") {
        Some("gold")
    } else if by_section(".note.mold") {
        Some("mold")
    } else if by_section(".note.lld") {
        Some("lld")
    } else {
        None
    };
    if let Some(f) = family {
        put_str(values, value_key!("elf.linker_family"), f);
        return;
    }
    // `.comment` fallback — covers GNU ld (no dedicated note) and
    // toolchains that append `ld.lld` / `mold` strings inline.
    let family = values
        .get_key(value_key!("elf.comment"))
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .find_map(|text| {
            let lower = text.to_lowercase();
            if text.contains("GNU gold") {
                Some("gold")
            } else if text.contains("LLD") || lower.contains("ld.lld") || lower.contains("lld ") {
                Some("lld")
            } else if lower.contains("mold ") || text.contains("mold") {
                Some("mold")
            } else if text.contains("GNU ld") {
                Some("ld")
            } else {
                None
            }
        });
    if let Some(family) = family {
        put_str(values, value_key!("elf.linker_family"), family);
    }
}

/// Best-effort distro/toolchain attribution from the `.comment`
/// banner strings already emitted under `elf.comment[]`. Surfaces
/// `elf.distro` (e.g. `wolfi`, `ubuntu`, `debian`, `alpine`, …),
/// `elf.toolchain_family` (`gcc` / `clang` / `apple_clang`), and
/// `elf.toolchain` (the family + version, e.g. `"gcc 13.2.0"`).
///
/// Trait authors who need finer-grained matching can regex against
/// the raw `elf.comment[]` entries; these are the common cases.
fn comment_fingerprint(values: &mut Values) {
    let joined: String = values
        .get_key(value_key!("elf.comment"))
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .collect::<Vec<_>>()
        .join("; ");
    if joined.is_empty() {
        return;
    }
    let lower = joined.to_lowercase();
    // Wolfi / Chainguard / Kali come before their parent distros —
    // Wolfi inherits Alpine's banner format, Kali inherits Debian's.
    let distro: Option<&str> = if lower.contains("wolfi") {
        Some("wolfi")
    } else if lower.contains("chainguard") {
        Some("chainguard")
    } else if lower.contains("kali") {
        Some("kali")
    } else if lower.contains("ubuntu") {
        Some("ubuntu")
    } else if lower.contains("debian") {
        Some("debian")
    } else if lower.contains("alpine") {
        Some("alpine")
    } else if lower.contains("red hat") || lower.contains("redhat") {
        Some("redhat")
    } else if lower.contains("rocky") {
        Some("rocky")
    } else if lower.contains("almalinux") {
        Some("almalinux")
    } else if lower.contains("amazon linux") {
        Some("amazon")
    } else if lower.contains("fedora") {
        Some("fedora")
    } else if lower.contains("suse") {
        Some("suse")
    } else if lower.contains("arch linux") || lower.contains("archlinux") {
        Some("archlinux")
    } else if lower.contains("gentoo") {
        Some("gentoo")
    } else if lower.contains("nixos") {
        Some("nixos")
    } else if lower.contains("openwrt") {
        Some("openwrt")
    } else {
        None
    };
    if let Some(d) = distro {
        put_str(values, value_key!("elf.distro"), d);
    }

    let (family, version) = if joined.starts_with("GCC:") || joined.contains("; GCC:") {
        let version = joined.find("GCC:").and_then(|start| {
            let rest = &joined[start + "GCC:".len()..];
            // Skip the parenthesized distro tag.
            let after_paren = match rest.find(')') {
                Some(p) => &rest[p + 1..],
                None => rest,
            };
            after_paren
                .split([';', ',', ' '])
                .find(|t| t.chars().next().is_some_and(|c| c.is_ascii_digit()))
                .map(|t| t.trim().to_string())
                .filter(|s| !s.is_empty())
        });
        (Some("gcc"), version)
    } else if joined.contains("Apple LLVM") || joined.contains("Apple clang") {
        let version = joined.find("version ").and_then(|pos| {
            let rest = &joined[pos + "version ".len()..];
            rest.split([' ', '(', ')'])
                .next()
                .map(|t| t.trim().to_string())
                .filter(|s| !s.is_empty())
        });
        (Some("apple_clang"), version)
    } else if joined.contains("clang version") {
        let version = joined.find("clang version ").and_then(|pos| {
            let rest = &joined[pos + "clang version ".len()..];
            rest.split([' ', '(', ')'])
                .next()
                .map(|t| t.trim().to_string())
                .filter(|s| !s.is_empty())
        });
        (Some("clang"), version)
    } else {
        (None, None)
    };
    if let Some(f) = family {
        put_str(values, value_key!("elf.toolchain_family"), f);
        if let Some(v) = version {
            put_str(values, value_key!("elf.toolchain"), format!("{f} {v}"));
        }
    }
}

/// `.comment` section content split on NUL — one entry per input
/// `.o` file's toolchain banner. Multiple distinct banners in the
/// same binary (e.g. `GCC: (Ubuntu …)` + `clang version …`) signal
/// that one or more object files were built outside the main
/// toolchain, the canonical xz-class supply-chain tampering tell.
fn comment(elf: &Elf<'_>, bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    let Some(data) = read_section(elf, bytes, ".comment") else {
        return;
    };
    let texts: Vec<String> = data
        .split(|&b| b == 0)
        .filter(|chunk| !chunk.is_empty())
        .filter_map(|chunk| std::str::from_utf8(chunk).ok())
        .filter(|s| !s.trim().is_empty())
        .map(str::to_string)
        .collect();
    if texts.is_empty() {
        return;
    }
    metrics.insert(metric!("elf.comment_entry_count"), texts.len() as f64);
    // `comment_distinct_count > 1` is the mixed-toolchain tell —
    // an unstripped object file linked into the binary carries its
    // own `GCC: (…)` / `clang version …` banner, so distinct count
    // above 1 means objects from multiple toolchains were merged.
    let distinct: std::collections::HashSet<&str> = texts.iter().map(String::as_str).collect();
    metrics.insert(metric!("elf.comment_distinct_count"), distinct.len() as f64);
    values.insert_key(
        value_key!("elf.comment"),
        JsonValue::Array(texts.into_iter().map(JsonValue::String).collect()),
    );
}

/// Verbatim `-frecord-gcc-switches` argv. Present when the source was
/// built with that flag (Fedora/RHEL default on most packages, opt-in
/// elsewhere). NULs separate argv entries — we render them as single
/// spaces and collapse internal runs of whitespace, so the value is a
/// single readable command line per CU. Strong attribution surface
/// when present, silent otherwise.
fn gcc_command_line(elf: &Elf<'_>, bytes: &[u8], values: &mut Values) {
    let Some(data) = read_section(elf, bytes, ".GCC.command.line") else {
        return;
    };
    let rendered: String = data
        .iter()
        .map(|&b| if b == 0 { ' ' } else { b as char })
        .collect();
    let trimmed = rendered.trim();
    if trimmed.is_empty() {
        return;
    }
    let collapsed: String = trimmed.split_whitespace().collect::<Vec<_>>().join(" ");
    values.insert_key(
        value_key!("elf.gcc_command_line"),
        JsonValue::String(collapsed),
    );
}

/// The name of section `sh`, cut to [`MAX_SECTION_NAME`] chars; empty when it
/// has none. The string table is attacker-supplied: `sh_name` may point into a
/// run holding no NUL, making a section's "name" the rest of the file, and
/// distinct headers may name every suffix of that run. Cutting by chars always
/// lands on a boundary; real names are a handful of bytes.
fn section_name<'a>(elf: &Elf<'a>, sh: &SectionHeader) -> &'a str {
    let full = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
    match full.char_indices().nth(MAX_SECTION_NAME) {
        Some((end, _)) => full.get(..end).unwrap_or(full),
        None => full,
    }
}

/// The first section header named `name`.
fn section_header<'e>(elf: &'e Elf<'_>, name: &str) -> Option<&'e SectionHeader> {
    elf.section_headers
        .iter()
        .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(name))
}

/// The file bytes section `sh` declares; `None` when they run past the file.
fn section_bytes<'a>(sh: &SectionHeader, bytes: &'a [u8]) -> Option<&'a [u8]> {
    let start = usize::try_from(sh.sh_offset).ok()?;
    let len = usize::try_from(sh.sh_size).ok()?;
    bytes.get(start..start.checked_add(len)?)
}

/// The file bytes of the first section named `name`; `None` when there is no
/// such section or its header points past the file.
fn read_section<'a>(elf: &Elf<'_>, bytes: &'a [u8], name: &str) -> Option<&'a [u8]> {
    section_bytes(section_header(elf, name)?, bytes)
}

/// Emit `elf.segments[]` — one entry per program header. Trait
/// authors match on segment kind + permissions + extent for
/// anti-debug / packer detection. Permissions are emitted both as a
/// 3-character `rwx` string (loader-conventional) and the structured
/// `flags[]` array; consumers pick whichever they prefer.
fn segments(elf: &Elf<'_>, values: &mut Values) {
    let segs: Vec<JsonValue> = elf
        .program_headers
        .iter()
        .map(|ph| {
            let mut entry = serde_json::Map::new();
            entry.insert(
                "type".into(),
                JsonValue::String(phdr_type_name(ph.p_type).to_string()),
            );
            entry.insert("vaddr".into(), JsonValue::Number(ph.p_vaddr.into()));
            entry.insert("paddr".into(), JsonValue::Number(ph.p_paddr.into()));
            entry.insert("file_offset".into(), JsonValue::Number(ph.p_offset.into()));
            entry.insert("file_size".into(), JsonValue::Number(ph.p_filesz.into()));
            entry.insert("memory_size".into(), JsonValue::Number(ph.p_memsz.into()));
            entry.insert("align".into(), JsonValue::Number(ph.p_align.into()));
            // PF_R = 4, PF_W = 2, PF_X = 1. Emit a `rwx`-style string
            // matching how readelf prints segment flags.
            let r = ph.p_flags & 0x4 != 0;
            let w = ph.p_flags & 0x2 != 0;
            let x = ph.p_flags & 0x1 != 0;
            let perms = format!(
                "{}{}{}",
                if r { "r" } else { "-" },
                if w { "w" } else { "-" },
                if x { "x" } else { "-" },
            );
            entry.insert("perms".into(), JsonValue::String(perms));
            entry.insert(
                "flags_hex".into(),
                JsonValue::String(format!("{:x}", ph.p_flags)),
            );
            JsonValue::Object(entry)
        })
        .collect();
    if !segs.is_empty() {
        values.insert_key(value_key!("elf.segments"), JsonValue::Array(segs));
    }
}

/// Emit `elf.sections[]` — one entry per section header, carrying every
/// `Elf64_Shdr` field. The cross-format `Sections` list (name/addr/
/// offset/size/flags/entropy) drives the `sections.*` metrics, but it
/// cannot carry ELF-only fields (`sh_type`, `sh_link`, `sh_info`,
/// `sh_addralign`, `sh_entsize`, the `sh_name` string-table index). This
/// array does, so a grafted section header, a relocated string table, or
/// any single field the section-header table changes is diff-visible.
/// Names use the same `MAX_SECTION_NAME` cut as `sections()` because the
/// string table is attacker-controlled and a `sh_name` can point at a
/// run with no NUL.
fn section_headers(elf: &Elf<'_>, values: &mut Values) {
    let secs: Vec<JsonValue> = elf
        .section_headers
        .iter()
        .map(|sh| {
            let name = section_name(elf, sh);
            let mut entry = serde_json::Map::new();
            entry.insert("name".into(), JsonValue::String(name.to_string()));
            entry.insert("name_offset".into(), JsonValue::Number(sh.sh_name.into()));
            entry.insert(
                "type".into(),
                JsonValue::String(shdr_type_name(sh.sh_type).to_string()),
            );
            entry.insert("type_raw".into(), JsonValue::Number(sh.sh_type.into()));
            entry.insert(
                "flags".into(),
                JsonValue::Array(
                    section_flags(sh.sh_flags)
                        .into_iter()
                        .map(|s| JsonValue::String(s.to_string()))
                        .collect(),
                ),
            );
            entry.insert(
                "flags_hex".into(),
                JsonValue::String(format!("{:x}", sh.sh_flags)),
            );
            entry.insert("addr".into(), JsonValue::Number(sh.sh_addr.into()));
            entry.insert("file_offset".into(), JsonValue::Number(sh.sh_offset.into()));
            entry.insert("size".into(), JsonValue::Number(sh.sh_size.into()));
            entry.insert("link".into(), JsonValue::Number(sh.sh_link.into()));
            entry.insert("info".into(), JsonValue::Number(sh.sh_info.into()));
            entry.insert(
                "addralign".into(),
                JsonValue::Number(sh.sh_addralign.into()),
            );
            entry.insert("entsize".into(), JsonValue::Number(sh.sh_entsize.into()));
            JsonValue::Object(entry)
        })
        .collect();
    if !secs.is_empty() {
        values.insert_key(value_key!("elf.sections"), JsonValue::Array(secs));
    }
}

/// Section-header type (`sh_type`) to conventional name. Unknown values
/// resolve to `"other"`; the raw number rides alongside in `type_raw`.
fn shdr_type_name(sh_type: u32) -> &'static str {
    use goblin::elf::section_header as sh;
    match sh_type {
        sh::SHT_NULL => "null",
        sh::SHT_PROGBITS => "progbits",
        sh::SHT_SYMTAB => "symtab",
        sh::SHT_STRTAB => "strtab",
        sh::SHT_RELA => "rela",
        sh::SHT_HASH => "hash",
        sh::SHT_DYNAMIC => "dynamic",
        sh::SHT_NOTE => "note",
        sh::SHT_NOBITS => "nobits",
        sh::SHT_REL => "rel",
        sh::SHT_SHLIB => "shlib",
        sh::SHT_DYNSYM => "dynsym",
        sh::SHT_INIT_ARRAY => "init_array",
        sh::SHT_FINI_ARRAY => "fini_array",
        sh::SHT_PREINIT_ARRAY => "preinit_array",
        sh::SHT_GROUP => "group",
        sh::SHT_SYMTAB_SHNDX => "symtab_shndx",
        sh::SHT_GNU_ATTRIBUTES => "gnu_attributes",
        sh::SHT_GNU_HASH => "gnu_hash",
        sh::SHT_GNU_LIBLIST => "gnu_liblist",
        sh::SHT_GNU_VERDEF => "gnu_verdef",
        sh::SHT_GNU_VERNEED => "gnu_verneed",
        sh::SHT_GNU_VERSYM => "gnu_versym",
        _ => "other",
    }
}

/// Map a PT_* program-header type constant to its conventional name.
fn phdr_type_name(p_type: u32) -> &'static str {
    use goblin::elf::program_header as ph;
    match p_type {
        ph::PT_NULL => "null",
        ph::PT_LOAD => "load",
        ph::PT_DYNAMIC => "dynamic",
        ph::PT_INTERP => "interp",
        ph::PT_NOTE => "note",
        ph::PT_SHLIB => "shlib",
        ph::PT_PHDR => "phdr",
        ph::PT_TLS => "tls",
        ph::PT_GNU_EH_FRAME => "gnu_eh_frame",
        ph::PT_GNU_STACK => "gnu_stack",
        ph::PT_GNU_RELRO => "gnu_relro",
        _ => "other",
    }
}

/// Whether a load segment or executable section contains any collected bytes.
fn has_present_load_or_code_bytes(elf: &Elf<'_>, file_len: usize) -> bool {
    let present = |offset: u64, size: u64| {
        size != 0 && usize::try_from(offset).is_ok_and(|offset| offset < file_len)
    };
    elf.program_headers.iter().any(|p| {
        p.p_type == goblin::elf::program_header::PT_LOAD && present(p.p_offset, p.p_filesz)
    }) || elf.section_headers.iter().any(|s| {
        s.sh_flags & u64::from(goblin::elf::section_header::SHF_EXECINSTR) != 0
            && s.sh_type != goblin::elf::section_header::SHT_NOBITS
            && present(s.sh_offset, s.sh_size)
    })
}

fn elf_header(elf: &Elf<'_>, values: &mut Values) {
    put_str(
        values,
        value_key!("elf.machine"),
        machine_string(elf.header.e_machine),
    );
    put_str(
        values,
        value_key!("elf.class"),
        if elf.is_64 { "elf64" } else { "elf32" },
    );
    put_str(
        values,
        value_key!("elf.endian"),
        if elf.little_endian { "little" } else { "big" },
    );
    put_str(
        values,
        value_key!("elf.type"),
        elf_type_string(elf.header.e_type),
    );
    put_u64(values, value_key!("elf.entry"), elf.header.e_entry);
    put_u64(
        values,
        value_key!("elf.version"),
        u64::from(elf.header.e_version),
    );
    // e_ident residue beyond class/endian: OS/ABI, its version, and the
    // EI_VERSION byte. A patched loader or a forged toolchain provenance
    // shows here, and `elf.ident_version` disagreeing with `elf.version`
    // is itself an anomaly.
    put_str(
        values,
        value_key!("elf.osabi"),
        osabi_string(elf.header.e_ident[7]),
    );
    put_u64(
        values,
        value_key!("elf.abi_version"),
        u64::from(elf.header.e_ident[8]),
    );
    put_u64(
        values,
        value_key!("elf.ident_version"),
        u64::from(elf.header.e_ident[6]),
    );
    // Table offsets and entity sizes. `e_shoff` is the section-header
    // table's file offset: appending infectors relocate it to EOF after
    // grafting a section, so a moved `elf.shoff` is a direct infection
    // tell. `e_phoff`, the per-entry sizes,
    // the header size, and `e_shstrndx` complete the ELF header so no
    // header field can change without a diff noticing.
    put_u64(values, value_key!("elf.phoff"), elf.header.e_phoff);
    put_u64(values, value_key!("elf.shoff"), elf.header.e_shoff);
    put_u64(
        values,
        value_key!("elf.shstrndx"),
        u64::from(elf.header.e_shstrndx),
    );
    put_u64(
        values,
        value_key!("elf.ehsize"),
        u64::from(elf.header.e_ehsize),
    );
    put_u64(
        values,
        value_key!("elf.phentsize"),
        u64::from(elf.header.e_phentsize),
    );
    put_u64(
        values,
        value_key!("elf.shentsize"),
        u64::from(elf.header.e_shentsize),
    );
    e_flags(elf, values);
}

/// Decode the `EI_OSABI` byte (`e_ident[7]`) to the conventional name.
/// Unknown values fall back to `osabi:<n>` so the raw value still diffs.
fn osabi_string(osabi: u8) -> String {
    let name = match osabi {
        0 => "sysv",
        1 => "hpux",
        2 => "netbsd",
        3 => "linux",
        4 => "gnu_hurd",
        6 => "solaris",
        7 => "aix",
        8 => "irix",
        9 => "freebsd",
        10 => "tru64",
        11 => "modesto",
        12 => "openbsd",
        13 => "openvms",
        14 => "nsk",
        15 => "aros",
        16 => "fenixos",
        17 => "cloudabi",
        64 => "arm_aeabi",
        97 => "arm",
        255 => "standalone",
        _ => return format!("osabi:{osabi}"),
    };
    name.to_string()
}

/// Per-architecture decode of `e_flags`. x86 / x86_64 / aarch64
/// don't use the field (always zero), so we don't bother emitting
/// `elf.e_flags` for them — the absence of the field IS the "no
/// arch flags" signal. ARM / MIPS / RISC-V carry meaningful ABI
/// bits here: ABI version (ARM EABI), float convention (ARM
/// soft/hard, MIPS FP64, RISC-V single/double/quad), endianness
/// hints, and ISA-extension markers.
fn e_flags(elf: &Elf<'_>, values: &mut Values) {
    let raw = elf.header.e_flags;
    if raw == 0 {
        return;
    }
    let machine = elf.header.e_machine;
    let mut flags: Vec<&'static str> = Vec::new();
    match machine {
        header::EM_ARM => decompose_arm_eflags(raw, &mut flags),
        header::EM_MIPS => decompose_mips_eflags(raw, &mut flags),
        header::EM_RISCV => decompose_riscv_eflags(raw, &mut flags),
        _ => {}
    }
    put_u64(values, value_key!("elf.e_flags_raw"), u64::from(raw));
    if !flags.is_empty() {
        values.insert_key(
            value_key!("elf.e_flags"),
            JsonValue::Array(
                flags
                    .into_iter()
                    .map(|s| JsonValue::String(s.to_string()))
                    .collect(),
            ),
        );
    }
}

fn decompose_arm_eflags(v: u32, out: &mut Vec<&'static str>) {
    // EABI version sits in the top byte. binutils prints it as
    // "Version5 EABI" — we use the canonical short name.
    let eabi = (v >> 24) & 0xff;
    if eabi != 0 {
        out.push(match eabi {
            1 => "eabi_v1",
            2 => "eabi_v2",
            3 => "eabi_v3",
            4 => "eabi_v4",
            5 => "eabi_v5",
            _ => "eabi_unknown",
        });
    }
    if v & 0x0000_0001 != 0 {
        out.push("relexec");
    }
    if v & 0x0000_0004 != 0 {
        out.push("interwork");
    }
    if v & 0x0000_0200 != 0 {
        out.push("soft_float");
    }
    if v & 0x0000_0400 != 0 {
        out.push("hard_float");
    }
    if v & 0x0040_0000 != 0 {
        out.push("le8");
    }
    if v & 0x0080_0000 != 0 {
        out.push("be8");
    }
}

fn decompose_mips_eflags(v: u32, out: &mut Vec<&'static str>) {
    if v & 0x0000_0001 != 0 {
        out.push("noreorder");
    }
    if v & 0x0000_0002 != 0 {
        out.push("pic");
    }
    if v & 0x0000_0004 != 0 {
        out.push("cpic");
    }
    if v & 0x0000_0020 != 0 {
        out.push("abi2_n32");
    }
    if v & 0x0000_0100 != 0 {
        out.push("32bit_mode");
    }
    if v & 0x0000_0200 != 0 {
        out.push("fp64");
    }
    if v & 0x0000_0400 != 0 {
        out.push("nan2008");
    }
    // ABI field (bits 0x0000_F000) — only the first few values are used.
    match (v >> 12) & 0xf {
        1 => out.push("abi_o32"),
        2 => out.push("abi_o64"),
        3 => out.push("abi_eabi32"),
        4 => out.push("abi_eabi64"),
        _ => {}
    }
}

fn decompose_riscv_eflags(v: u32, out: &mut Vec<&'static str>) {
    if v & 0x0000_0001 != 0 {
        out.push("rvc");
    }
    if v & 0x0000_0008 != 0 {
        out.push("rve");
    }
    if v & 0x0000_0010 != 0 {
        out.push("tso");
    }
    // Float ABI in bits 0x6.
    match (v >> 1) & 0x3 {
        1 => out.push("fp_single"),
        2 => out.push("fp_double"),
        3 => out.push("fp_quad"),
        _ => {}
    }
}

fn sections(elf: &Elf<'_>, bytes: &[u8], sections_out: &mut Vec<Section>) {
    // Entropy is O(section length) and section ranges are attacker-supplied:
    // nothing requires them to be disjoint, so `e_shnum` headers can all cover
    // the same megabytes and cost `e_shnum × filesize` — measured at 11.8 s for
    // 2000 headers over one 8 MB range. An honest ELF's file-backed sections are
    // disjoint slices of the file, so its own length is the exact budget they
    // need and this never bites a real binary.
    let mut entropy_budget = bytes.len() as u64;
    for sh in &elf.section_headers {
        // `section_name` cuts the name: names are attacker-controlled
        // string-table runs, and distinct headers naming every suffix of one
        // run to EOF would otherwise turn a few MB of input into hundreds of
        // MB of JSON. Real names are a handful of bytes.
        let name = section_name(elf, sh).to_owned();
        // SHT_NOBITS sections have no file bytes. Other types
        // occupy `sh_offset..sh_offset + sh_size` in the file.
        let (file_offset, file_size) = if sh.sh_type == goblin::elf::section_header::SHT_NOBITS {
            (sh.sh_offset, 0)
        } else {
            (sh.sh_offset, sh.sh_size)
        };
        // Charging `min` rather than skipping outright means at most one
        // section overdraws, so an honest trailing section is never dropped.
        let entropy = (file_size > 0 && entropy_budget > 0).then(|| {
            entropy_budget -= file_size.min(entropy_budget);
            section_entropy(bytes, file_offset, file_size)
        });
        sections_out.push(Section {
            name,
            vaddr: sh.sh_addr,
            vsize: sh.sh_size,
            file_offset,
            file_size,
            flags: section_flags(sh.sh_flags),
            flags_raw: Some(sh.sh_flags),
            entropy,
        });
    }
}

/// File offset one past the last byte the image itself accounts for,
/// beyond its sections: the ELF header, the program-header table, every
/// segment's on-disk extent, and the section-header table — which the
/// linker writes after all sections, at EOF. Only bytes past this are
/// appended payload, i.e. an overlay. Declared extents are not clamped
/// to the input: an end past EOF simply means there is no overlay.
fn image_end_of(elf: &Elf<'_>) -> u64 {
    let h = &elf.header;
    let table_end = |off: u64, count: usize, entsize: u16| {
        if off == 0 || count == 0 {
            return 0;
        }
        off.saturating_add((count as u64).saturating_mul(u64::from(entsize)))
    };
    let mut end = u64::from(h.e_ehsize)
        .max(table_end(
            h.e_phoff,
            elf.program_headers.len(),
            h.e_phentsize,
        ))
        // `section_headers.len()` rather than `e_shnum`: with >= 0xff00
        // sections the real count lives in section 0's `sh_size`.
        .max(table_end(
            h.e_shoff,
            elf.section_headers.len(),
            h.e_shentsize,
        ));
    for ph in &elf.program_headers {
        if ph.p_filesz > 0 {
            end = end.max(ph.p_offset.saturating_add(ph.p_filesz));
        }
    }
    end
}

/// Map a virtual address to a file offset through the `PT_LOAD` segments: the
/// one VA→offset resolver every ELF reader here shares.
///
/// Segments, not sections, because they survive section-header stripping:
/// release and packed binaries routinely drop the section table while keeping
/// the loadable segments the dynamic linker needs. `None` when no `PT_LOAD`
/// segment backs `va` with file bytes (a `.bss`-only address, say).
fn load_segment_va_to_offset(elf: &Elf<'_>, va: u64) -> Option<u64> {
    elf.program_headers
        .iter()
        .filter(|p| p.p_type == goblin::elf::program_header::PT_LOAD)
        .find_map(|p| {
            let delta = va.checked_sub(p.p_vaddr)?;
            (delta < p.p_filesz).then(|| p.p_offset.saturating_add(delta))
        })
}

fn machine_string(machine: u16) -> &'static str {
    // Subset of `EM_*` constants from elf.h.
    match machine {
        header::EM_X86_64 => "x86_64",
        header::EM_386 => "i386",
        header::EM_ARM => "arm",
        header::EM_AARCH64 => "aarch64",
        header::EM_PPC64 => "powerpc64",
        header::EM_PPC => "powerpc",
        header::EM_MIPS => "mips",
        header::EM_RISCV => "riscv",
        header::EM_S390 => "s390",
        header::EM_SPARCV9 => "sparc64",
        header::EM_LOONGARCH => "loongarch",
        header::EM_VIDEOCORE3 => "videocore3",
        header::EM_QDSP6 => "qdsp6",
        header::EM_XTENSA => "xtensa",
        _ => "unknown",
    }
}

fn elf_type_string(t: u16) -> &'static str {
    match t {
        header::ET_NONE => "none",
        header::ET_REL => "relocatable",
        header::ET_EXEC => "executable",
        header::ET_DYN => "dynamic",
        header::ET_CORE => "core",
        _ => "unknown",
    }
}

fn section_flags(flags: u64) -> Vec<SectionFlag> {
    [
        (0x1, SectionFlag::Writable),
        (0x2, SectionFlag::Alloc),
        (0x4, SectionFlag::Executable),
        (0x10, SectionFlag::Merge),
        (0x20, SectionFlag::Strings),
        (0x40, SectionFlag::InfoLink),
        (0x100, SectionFlag::Tls),
    ]
    .into_iter()
    .filter_map(|(bit, flag)| (flags & bit != 0).then_some(flag))
    .collect()
}

#[cfg(test)]
mod tests;
