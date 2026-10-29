//! Numeric `elf.*` and cross-format `binary.*` metrics over the header,
//! program and section tables: hardening flags, entry placement, table
//! anomalies and file-layout invariants that carving, appending, packing and
//! infection break.

use goblin::elf::note::Note;
use goblin::elf::{Elf, header, program_header};
use serde_json::Value as JsonValue;

use super::{RangeCover, overlapping, section_header, section_name};
use crate::formats::common::{hex_encode, put_str};
use crate::metric;
use crate::output::{Metrics, Values};
use crate::value_key;

/// Flat `elf.*` numeric metrics — the integer-valued counterparts to
/// the string facts that already live on the `values` tree
/// (`elf.machine`, `elf.type`, …), which rules threshold on: segment
/// permissions and entry placement, header table anomalies, section
/// presence flags and note counts.
pub(super) fn header_and_layout(
    elf: &Elf<'_>,
    segment_notes: &[Note<'_>],
    metrics: &mut Metrics,
    values: &mut Values,
) {
    // Header constants. `elf.machine` and `elf.type` already live on
    // the values tree as strings — the numeric forms add nothing.
    metrics.insert(
        metric!("elf.bits"),
        f64::from(if elf.is_64 { 64u32 } else { 32u32 }),
    );
    metrics.insert(
        metric!("elf.little_endian"),
        f64::from(u8::from(elf.little_endian)),
    );
    metrics.insert(metric!("elf.entry"), elf.header.e_entry as f64);
    metrics.insert(
        metric!("elf.program_header_count"),
        elf.program_headers.len() as f64,
    );
    // Section count flows through `sections.count` (cross-format aggregate
    // emitted by `emit_section_metrics`). Don't dual-emit `elf.section_count`.
    metrics.insert(
        metric!("elf.section_relocation_group_count"),
        elf.shdr_relocs.len() as f64,
    );

    // Program headers / segments. PT_LOAD = 1, PT_GNU_STACK = 0x6474_e551.
    // PF_X = 1, PF_W = 2.
    let mut max_file_size: u64 = 0;
    let mut max_memory_size: u64 = 0;
    let mut has_gnu_stack = false;
    let mut nx_enabled = true; // default: no executable stack signal
    let mut wx_segment_count: u64 = 0;
    let mut executable_segment_count: u64 = 0;
    let mut entry_in_writable_segment = false;
    let mut entry_in_exec_segment = false;
    let mut entry_in_any_segment = false;
    let mut interp_count: u64 = 0;
    let mut min_load_offset: Option<u64> = None;
    let mut load_ranges: Vec<(u64, u64, usize)> = Vec::new();
    let mut last_load_vaddr: u64 = 0;
    let mut last_load_idx: Option<usize> = None;
    let mut entry_load_idx: Option<usize> = None;
    let entry = elf.header.e_entry;
    for (idx, ph) in elf.program_headers.iter().enumerate() {
        if ph.p_type == program_header::PT_LOAD {
            max_file_size = max_file_size.max(ph.p_filesz);
            max_memory_size = max_memory_size.max(ph.p_memsz);
            let writable = ph.p_flags & 0x2 != 0;
            let executable = ph.p_flags & 0x1 != 0;
            if writable && executable {
                wx_segment_count += 1;
            }
            if executable {
                executable_segment_count += 1;
            }
            let span = ph.p_memsz.max(ph.p_filesz);
            let end = ph.p_vaddr.saturating_add(span);
            load_ranges.push((ph.p_vaddr, end, idx));
            if entry != 0 && entry >= ph.p_vaddr && entry < end {
                entry_in_any_segment = true;
                if writable {
                    entry_in_writable_segment = true;
                }
                if executable {
                    entry_in_exec_segment = true;
                }
                entry_load_idx = Some(idx);
            }
            if last_load_idx.is_none() || ph.p_vaddr > last_load_vaddr {
                last_load_idx = Some(idx);
                last_load_vaddr = ph.p_vaddr;
            }
            min_load_offset = Some(
                min_load_offset
                    .map(|m| m.min(ph.p_offset))
                    .unwrap_or(ph.p_offset),
            );
        }
        if ph.p_type == program_header::PT_GNU_STACK {
            has_gnu_stack = true;
            // PF_X = 1; an executable GNU stack disables NX.
            if ph.p_flags & 0x1 != 0 {
                nx_enabled = false;
            }
        }
        if ph.p_type == program_header::PT_INTERP {
            interp_count = interp_count.saturating_add(1);
        }
    }
    metrics.insert(
        metric!("elf.load_segment_max_file_size"),
        max_file_size as f64,
    );
    metrics.insert(
        metric!("elf.load_segment_max_memory_size"),
        max_memory_size as f64,
    );
    metrics.insert(metric!("elf.nx_enabled"), f64::from(u8::from(nx_enabled)));
    metrics.insert(
        metric!("elf.executable_stack"),
        f64::from(u8::from(!nx_enabled)),
    );
    metrics.insert(metric!("elf.wx_segment_count"), wx_segment_count as f64);
    // Executable PT_LOAD segments. Modern toolchains emit exactly one
    // (with `-z separate-code`); a second is the note-cavity / appended
    // parasite tell — a grafted R+X segment beside the real text — and it
    // fires even for an EPO infector that leaves the entry in `.text`.
    metrics.insert(
        metric!("elf.executable_segment_count"),
        executable_segment_count as f64,
    );
    if entry_in_writable_segment {
        metrics.insert(metric!("elf.entry_in_writable_segment"), 1.0);
    }
    if entry != 0 && !entry_in_any_segment {
        metrics.insert(metric!("elf.entry_outside_segments"), 1.0);
    }
    // Entry landing in a loadable segment that is not executable — an
    // entry redirected into data. The loader would fault on a normal
    // system, so no honest toolchain emits it; EPO/patch infectors that
    // point the entry at a writable data blob do.
    if entry != 0 && entry_in_any_segment && !entry_in_exec_segment {
        metrics.insert(metric!("elf.entry_in_non_executable_segment"), 1.0);
    }
    if interp_count > 1 {
        metrics.insert(metric!("elf.multiple_pt_interp"), 1.0);
    }
    // Entry-in-last-segment: the EP's containing PT_LOAD is the one with
    // the highest p_vaddr. UPX-style packers stash the unpacker stub
    // there; vendor binaries land EPs in earlier segments.
    if let (Some(ep_idx), Some(last_idx)) = (entry_load_idx, last_load_idx) {
        if ep_idx == last_idx {
            metrics.insert(metric!("elf.entry_in_last_segment"), 1.0);
        }
    }
    // PT_LOAD segments whose address ranges intersect another's.
    let overlap = overlapping(load_ranges);
    if !overlap.is_empty() {
        metrics.insert(metric!("elf.segment_overlap_count"), overlap.len() as f64);
        values.insert_key(
            value_key!("elf.overlapping_segments"),
            overlap
                .into_iter()
                .map(|i| JsonValue::String(format!("PT_LOAD#{i}")))
                .collect(),
        );
    }
    // First-segment gap — bytes between header table end and the first
    // PT_LOAD's file offset. Non-zero is a "header cave".
    let header_end = elf
        .header
        .e_phoff
        .saturating_add(u64::from(elf.header.e_phnum) * u64::from(elf.header.e_phentsize));
    if let Some(first_off) = min_load_offset {
        if first_off > header_end {
            metrics.insert(
                metric!("elf.first_segment_gap"),
                (first_off - header_end) as f64,
            );
        }
    }
    // Section header count mismatch — `e_shnum` vs walked sections.
    if usize::from(elf.header.e_shnum) != elf.section_headers.len() {
        metrics.insert(metric!("elf.section_header_count_mismatch"), 1.0);
    }
    // Program header count mismatch — `e_phnum` vs walked segments. The
    // symmetric partner of the section check above; a header table that
    // claims more entries than parse is corruption or table tampering.
    if usize::from(elf.header.e_phnum) != elf.program_headers.len() {
        metrics.insert(metric!("elf.program_header_count_mismatch"), 1.0);
    }
    // Section-name string table index past the section table. A loader
    // reading section names would walk off the end; benign toolchains
    // never emit this. `e_shstrndx == 0` with sections present is the
    // "no names" convention, not an error, so only flag out-of-range.
    if elf.header.e_shnum > 0 && elf.header.e_shstrndx >= elf.header.e_shnum {
        metrics.insert(metric!("elf.shstrndx_out_of_range"), 1.0);
    }
    // e_ident padding (`EI_PAD`, bytes 9..16) is zero in every toolchain
    // output; a non-zero byte there is a hidden-data / tamper channel.
    // Surface both the flag and the bytes so a change diffs.
    if elf.header.e_ident[9..16].iter().any(|&b| b != 0) {
        metrics.insert(metric!("elf.ident_pad_nonzero"), 1.0);
        put_str(
            values,
            value_key!("elf.ident_pad"),
            hex_encode(&elf.header.e_ident[9..16]),
        );
    }
    // ET_REL (relocatable object) files legitimately omit PT_GNU_STACK
    // because they have no program headers; only flag absence for
    // ET_EXEC / ET_DYN.
    let stack_section_absent = !has_gnu_stack && elf.header.e_type != header::ET_REL;
    metrics.insert(
        metric!("elf.no_gnu_stack"),
        f64::from(u8::from(stack_section_absent)),
    );

    // Section presence flags + note count + entry-section lookup.
    // `SHF_WRITE = 0x1`, `SHF_COMPRESSED = 0x800`.
    const SHF_WRITE: u64 = 0x1;
    const SHF_COMPRESSED: u64 = 0x800;
    let mut has_plt = false;
    let mut has_got = false;
    let mut has_eh_frame = false;
    let mut has_note = false;
    let mut note_count: u64 = 0;
    let mut entry_section: Option<String> = None;
    let mut has_dot_hash = false;
    let mut has_gnu_hash_sect = false;
    let mut has_symtab = false;
    let mut has_debuglink = false;
    let mut has_rustc_section = false;
    let mut text_writable = false;
    let mut rodata_writable = false;
    let mut debug_section_count: u64 = 0;
    let mut compressed_count: u64 = 0;
    let mut versym_size: u64 = 0;
    let mut name_seen: std::collections::HashMap<&str, u32> = std::collections::HashMap::new();
    let entry = elf.header.e_entry;
    for sh in elf.section_headers.iter() {
        let name = section_name(elf, sh);
        if !name.is_empty() {
            *name_seen.entry(name).or_default() += 1;
        }
        if sh.sh_flags & SHF_COMPRESSED != 0 {
            compressed_count = compressed_count.saturating_add(1);
        }
        match name {
            ".plt" => has_plt = true,
            ".got" | ".got.plt" => has_got = true,
            ".eh_frame" => has_eh_frame = true,
            ".hash" => has_dot_hash = true,
            ".gnu.hash" => has_gnu_hash_sect = true,
            ".symtab" => has_symtab = true,
            ".gnu_debuglink" => has_debuglink = true,
            ".rustc" => has_rustc_section = true,
            ".gnu.version" => versym_size = sh.sh_size,
            ".text" if sh.sh_flags & SHF_WRITE != 0 => text_writable = true,
            ".rodata" if sh.sh_flags & SHF_WRITE != 0 => rodata_writable = true,
            n if n.starts_with(".debug") || n.starts_with(".zdebug") => {
                debug_section_count = debug_section_count.saturating_add(1);
            }
            _ => {}
        }
        if name.starts_with(".note") {
            has_note = true;
            // SHT_NOTE = 7. Each note section can hold multiple notes;
            // the byte count is approximate (real walk requires
            // `iter_note_headers`, which we tally separately below).
            if sh.sh_type == 7 && sh.sh_size > 0 {
                note_count = note_count.saturating_add(1);
            }
        }
        if entry_section.is_none()
            && entry != 0
            && sh.sh_size > 0
            && entry >= sh.sh_addr
            && entry < sh.sh_addr.saturating_add(sh.sh_size)
        {
            entry_section = Some(name.to_string());
        }
    }
    metrics.insert(metric!("elf.has_plt"), f64::from(u8::from(has_plt)));
    metrics.insert(metric!("elf.has_got"), f64::from(u8::from(has_got)));
    metrics.insert(
        metric!("elf.has_eh_frame"),
        f64::from(u8::from(has_eh_frame)),
    );
    metrics.insert(metric!("elf.has_note"), f64::from(u8::from(has_note)));
    if has_debuglink {
        metrics.insert(metric!("elf.has_debuglink"), 1.0);
    }
    if has_symtab {
        metrics.insert(metric!("elf.has_symtab"), 1.0);
    }
    if has_rustc_section {
        metrics.insert(metric!("elf.has_rustc_section"), 1.0);
    }
    if has_dot_hash && has_gnu_hash_sect {
        metrics.insert(metric!("elf.has_both_hash_tables"), 1.0);
    }
    if text_writable {
        metrics.insert(metric!("elf.text_section_writable"), 1.0);
    }
    if rodata_writable {
        metrics.insert(metric!("elf.rodata_writable"), 1.0);
    }
    if debug_section_count > 0 {
        metrics.insert(
            metric!("elf.debug_section_count"),
            debug_section_count as f64,
        );
    }
    if compressed_count > 0 {
        metrics.insert(
            metric!("elf.compressed_section_count"),
            compressed_count as f64,
        );
    }
    // Each `.gnu.version` entry is a 16-bit half per dynamic symbol.
    if versym_size > 0 {
        metrics.insert(metric!("elf.dt_versym_count"), (versym_size / 2) as f64);
    }
    let dup_count = name_seen.values().filter(|&&c| c > 1).count() as u64;
    if dup_count > 0 {
        metrics.insert(
            metric!("elf.duplicate_section_name_count"),
            dup_count as f64,
        );
    }

    // Exact note count from the PT_NOTE walk. Falls back to the
    // section-level approximation above when that walk found nothing.
    if !segment_notes.is_empty() {
        note_count = segment_notes.len() as u64;
    }
    metrics.insert(metric!("elf.note_count"), note_count as f64);

    if let Some(name) = entry_section {
        // Entry points land in a code section — `.text`, occasionally
        // `.init`/`.plt`. An entry resolving into a section outside the
        // toolchain allowlist (`.attack`, a random appended name) is the
        // entry-redirection tell shared by note-cavity, EPO, and appending
        // infectors. Reuses the single well-known-section source of truth.
        if !crate::is_well_known_section_name(&name) {
            metrics.insert(metric!("elf.entry_in_nonstandard_section"), 1.0);
        }
        put_str(values, value_key!("elf.entry_section"), &name);
    } else if entry != 0 && entry_in_any_segment && elf.section_headers.len() > 1 {
        // The entry lands inside a loadable segment but no section covers
        // it, even though a real section table is present. That is the
        // note-cavity / appender infection against a target whose section
        // headers survive: the injector grafts the executable segment and
        // redirects the entry but omits a covering section (its `skip_shdr`
        // path), so `entry_in_nonstandard_section` never fires. Flag it.
        metrics.insert(metric!("elf.entry_outside_sections"), 1.0);
    }
}

/// Symbol-table + relocation-table counts. Cheap structural facts
/// goblin already has in hand; emitting them as flat metrics lets
/// trait engines threshold on "is the binary stripped" /
/// "does it have an unusual number of relocations" without walking
/// the dynsym table themselves.
pub(super) fn table_counts(elf: &Elf<'_>, metrics: &mut Metrics) {
    metrics.insert(metric!("elf.dynsym_count"), elf.dynsyms.len() as f64);
    metrics.insert(metric!("elf.symtab_count"), elf.syms.len() as f64);
    metrics.insert(metric!("elf.dynrela_count"), elf.dynrelas.len() as f64);
    metrics.insert(metric!("elf.dynrel_count"), elf.dynrels.len() as f64);
    metrics.insert(metric!("elf.pltreloc_count"), elf.pltrelocs.len() as f64);
    // DT_NEEDED entries are this ELF's shared-library dependencies.
    // Flows through the cross-format `dependencies.count` metric.
    metrics.insert(metric!("dependencies.count"), elf.libraries.len() as f64);
}

/// Content contracts for split native-image members, independent of filenames.
pub(super) fn member_layout(elf: &Elf<'_>, file_len: usize, metrics: &mut Metrics) {
    use goblin::elf::program_header::{PT_LOAD, PT_NULL};
    let loads: Vec<_> = elf
        .program_headers
        .iter()
        .filter(|p| p.p_type == PT_LOAD && p.p_filesz != 0)
        .collect();
    let missing_load_bytes = !loads.is_empty()
        && loads
            .iter()
            .all(|p| !usize::try_from(p.p_offset).is_ok_and(|offset| offset < file_len));
    metrics.insert(
        metric!("elf.load_segments_without_member_bytes"),
        f64::from(u8::from(missing_load_bytes)),
    );

    // The Linux Qualcomm MDT loader reads header/hash metadata separately
    // from PT_LOAD bytes in sibling bNN members. This observed variant has
    // private PHDR/HASH types and a header span covering the program table.
    // https://github.com/torvalds/linux/blob/master/drivers/soc/qcom/mdt_loader.c
    const TYPE_MASK: u32 = 7 << 24;
    const TYPE_PHDR: u32 = 7 << 24;
    const TYPE_HASH: u32 = 2 << 24;
    let table_end = u64::from(elf.header.e_phentsize)
        .checked_mul(u64::from(elf.header.e_phnum))
        .and_then(|size| elf.header.e_phoff.checked_add(size));
    let contract =
        !elf.is_64
            && elf.header.e_phentsize == 32
            && elf.program_headers.len() >= 3
            && !loads.is_empty()
            && table_end.is_some_and(|end| {
                elf.header.e_phoff >= u64::from(elf.header.e_ehsize)
                    && usize::try_from(end).is_ok_and(|end| end <= file_len)
            })
            && elf.program_headers.first().is_some_and(|p| {
                p.p_type == PT_NULL
                    && p.p_offset == 0
                    && p.p_flags & TYPE_MASK == TYPE_PHDR
                    && Some(p.p_filesz) == table_end
            })
            && elf.program_headers.iter().skip(1).any(|p| {
                p.p_type == PT_NULL && p.p_filesz != 0 && p.p_flags & TYPE_MASK == TYPE_HASH
            });
    metrics.insert(
        metric!("elf.qcom_mdt_header_layout"),
        f64::from(u8::from(contract)),
    );
}

/// Cross-format `binary.*` metrics derivable from ELF header state.
pub(super) fn binary_flags(elf: &Elf<'_>, section_headers_truncated: bool, metrics: &mut Metrics) {
    // PIE: dynamically-linked executable (`ET_DYN` + `PT_INTERP`).
    // A shared library is also `ET_DYN` but has no interpreter.
    let is_pie = elf.header.e_type == header::ET_DYN && elf.interpreter.is_some();
    metrics.insert(metric!("binary.is_pie"), f64::from(u8::from(is_pie)));

    // The segment-only parse deliberately discards the declared section
    // table. Its missing names and symbols are unknown, not absent.
    if section_headers_truncated {
        return;
    }

    // Observe absence of the full .symtab. A header member may never have
    // contained one; this does not establish prior execution of strip.
    let has_symtab = section_header(elf, ".symtab").is_some();
    metrics.insert(
        metric!("binary.full_symbol_table_absent_or_empty"),
        f64::from(u8::from(!has_symtab || elf.syms.is_empty())),
    );
    // The cross-format name for the same absence: `.symtab` is missing,
    // which says nothing about whether `strip` ever ran.
    metrics.insert(
        metric!("binary.is_stripped"),
        f64::from(u8::from(!has_symtab)),
    );
}

/// Names of common toolchain metadata sections absent from this collected ELF.
/// Absence alone does not prove a compiler produced them, a stripping tool
/// removed them, or load bytes outside the collected member lack those records.
pub(super) fn absent_metadata(elf: &Elf<'_>, values: &mut Values, metrics: &mut Metrics) {
    // This bounded catalog reports each section independently. Debug builds,
    // release builds and firmware members may have different original sets.
    const EXPECTED: &[&str] = &[
        ".symtab",
        ".strtab",
        ".comment",
        ".debug_info",
        ".debug_line",
        ".debug_str",
        ".debug_abbrev",
        ".note.gnu.gold-version",
    ];

    let present: std::collections::HashSet<&str> = elf
        .section_headers
        .iter()
        .map(|sh| section_name(elf, sh))
        .collect();

    let stripped: Vec<JsonValue> = EXPECTED
        .iter()
        .filter(|name| !present.contains(*name))
        .map(|name| JsonValue::String((*name).to_string()))
        .collect();

    metrics.insert(
        metric!("elf.absent_metadata_section_count"),
        stripped.len() as f64,
    );
    // The same absence under the `stripped_*` names rules match on; neither
    // identifies a stripping operation.
    metrics.insert(
        metric!("elf.stripped_metadata_section_count"),
        stripped.len() as f64,
    );
    if !stripped.is_empty() {
        values.insert_key(
            value_key!("elf.absent_metadata_sections"),
            JsonValue::Array(stripped.clone()),
        );
        values.insert_key(
            value_key!("elf.stripped_metadata_sections"),
            JsonValue::Array(stripped),
        );
    }
    // A present .symtab with an absent .comment or .debug_info is a shape
    // observation; it does not establish that any tool ran.
    let symtab_present = present.contains(".symtab");
    let debug_or_comment_gone = !present.contains(".comment") || !present.contains(".debug_info");
    metrics.insert(
        metric!("elf.stripped_with_symtab"),
        f64::from(u8::from(symtab_present && debug_or_comment_gone)),
    );
}

/// File-layout anomalies over the section table, keyed by file offset:
/// sections whose bytes run past EOF, `SHF_ALLOC` sections mapped by no
/// `PT_LOAD`, and mutually overlapping section ranges. Toolchains lay
/// sections out as disjoint, in-bounds slices, each allocatable one
/// inside a load segment; carving, appending, and packing break those
/// invariants. NOBITS sections (`.bss`, `.tbss`) own no file bytes and
/// are skipped.
pub(super) fn section_file_anomalies(elf: &Elf<'_>, bytes: &[u8], metrics: &mut Metrics) {
    use goblin::elf::program_header::PT_LOAD;
    const SHT_NOBITS: u32 = 8;
    const SHF_ALLOC: u64 = 0x2;
    let file_len = bytes.len() as u64;

    let load_ranges = RangeCover::new(
        elf.program_headers
            .iter()
            .filter(|ph| ph.p_type == PT_LOAD)
            .map(|ph| (ph.p_offset, ph.p_offset.saturating_add(ph.p_filesz)))
            .collect(),
    );

    let mut past_eof = 0u64;
    let mut uncovered_alloc = 0u64;
    let mut ranges: Vec<(u64, u64, usize)> = Vec::new();
    for (idx, sh) in elf.section_headers.iter().enumerate() {
        if sh.sh_type == SHT_NOBITS || sh.sh_size == 0 {
            continue;
        }
        let start = sh.sh_offset;
        let end = sh.sh_offset.saturating_add(sh.sh_size);
        if end > file_len {
            past_eof += 1;
        }
        if sh.sh_flags & SHF_ALLOC != 0
            && !load_ranges.is_empty()
            && !load_ranges.contains(start, end)
        {
            uncovered_alloc += 1;
        }
        ranges.push((start, end, idx));
    }

    // Sections whose file ranges intersect another's, counted once each,
    // as `elf.segment_overlap_count` counts segments.
    let overlap = overlapping(ranges);

    if past_eof > 0 {
        metrics.insert(metric!("elf.section_past_eof_count"), past_eof as f64);
    }
    if uncovered_alloc > 0 {
        metrics.insert(
            metric!("elf.uncovered_alloc_section_count"),
            uncovered_alloc as f64,
        );
    }
    if !overlap.is_empty() {
        metrics.insert(metric!("elf.section_overlap_count"), overlap.len() as f64);
    }
}
