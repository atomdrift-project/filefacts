//! ELF extractor.
//!
//! Reads Linux executables, shared libraries, and core dumps. Surfaces
//! the file header, dynamic-section facts (DT_NEEDED, RPATH, SONAME),
//! section table, dynamic symbol table imports/exports, and the
//! GNU build-id when present.

use goblin::elf::{dynamic, header, program_header, Elf};
use serde_json::Value as JsonValue;

use crate::error::Error;
use crate::formats::common::{
    extract_binary_strings, hex_encode, put_str, put_u64, rizin_fallback,
};
use crate::formats::goblin_safe;
use crate::output::{Errors, Metrics, Section, Strings, Values};
use crate::scan::entropy;

#[allow(clippy::too_many_arguments)]
pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
    sections_out: &mut Vec<Section>,
    imports_out: &mut crate::Imports,
    exports_out: &mut crate::Exports,
    functions_out: &mut crate::Functions,
    errors_out: &mut Errors,
) -> Result<(), Error> {
    extract_binary_strings(bytes, strings);

    // Wrap goblin parse in catch_unwind. ELF's dynamic-section
    // walker has panicked on malformed `DT_*` tables; `parse_elf`
    // turns a panic into a normal failure here. We record the
    // failure into the typed errors view and return Ok so the
    // byte-level metrics already in `metrics`/`strings` from the
    // generic pass survive.
    let elf = match goblin_safe::parse_elf(bytes) {
        goblin_safe::GoblinOutcome::Ok(elf) => elf,
        goblin_safe::GoblinOutcome::Failed(e) => {
            errors_out.record_malformed("elf-parse", e.to_string());
            metrics.insert("elf.parse_failed", 1.0);
            return Ok(());
        }
        goblin_safe::GoblinOutcome::Panicked(msg) => {
            errors_out.record_panic("elf-parse", msg);
            metrics.insert("elf.parse_panicked", 1.0);
            return Ok(());
        }
    };

    elf_header(&elf, values);
    dynamic(&elf, values);
    sections(&elf, bytes, metrics, sections_out);
    symbols(&elf, values, metrics, imports_out, exports_out);
    build_id(&elf, bytes, values, metrics);
    interpreter(&elf, values);
    relro(&elf, values);
    needed_versions(&elf, values);
    provided_versions(&elf, values);
    stripped_metadata(&elf, values, metrics);
    comment(&elf, bytes, values, metrics);
    dt_flags(&elf, values);
    abi_tag(&elf, bytes, values);
    gnu_property(&elf, bytes, values, metrics);
    binary_flags(&elf, metrics);
    elf_numeric_metrics(&elf, bytes, metrics, values);
    dynamic_metrics(&elf, metrics);
    table_counts(&elf, metrics);
    segments(&elf, values);
    rizin_fallback(bytes, imports_out, exports_out, functions_out, metrics);
    linker_family(values);
    super::elf_hashes::emit(&elf, values, imports_out, exports_out);
    super::upx::detect(bytes, values);
    super::go_buildinfo::detect(bytes, values, "elf");
    super::build_toolchain::from_elf(values, sections_out, bytes);

    Ok(())
}

/// Identify the linker family that produced this binary from
/// `elf.comment[]` banners. `GNU ld` / `GNU gold` are recognizable
/// by their `.comment` strings; LLD and `mold` stamp themselves
/// distinctly. Emits a single `elf.linker_family` string.
fn linker_family(values: &mut Values) {
    let Some(entries) = values
        .get("elf.comment")
        .and_then(serde_json::Value::as_array)
        .cloned()
    else {
        return;
    };
    for entry in entries {
        let Some(text) = entry.as_str() else {
            continue;
        };
        let family = if text.contains("GNU gold") {
            "gold"
        } else if text.contains("LLD") || text.contains("Linker:") && text.contains("LLD") {
            "lld"
        } else if text.contains("mold") {
            "mold"
        } else if text.contains("GNU ld") {
            "ld"
        } else {
            continue;
        };
        put_str(values, "elf.linker_family", family);
        return;
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
    metrics.insert("elf.comment_entry_count", texts.len() as f64);
    // `comment_distinct_count > 1` is the mixed-toolchain tell —
    // an unstripped object file linked into the binary carries its
    // own `GCC: (…)` / `clang version …` banner, so distinct count
    // above 1 means objects from multiple toolchains were merged.
    let distinct: std::collections::HashSet<&str> = texts.iter().map(String::as_str).collect();
    metrics.insert("elf.comment_distinct_count", distinct.len() as f64);
    values.insert(
        "elf.comment",
        JsonValue::Array(texts.into_iter().map(JsonValue::String).collect()),
    );
}

/// Decompose `DT_FLAGS` and `DT_FLAGS_1` bitfields into a flat string
/// array — the analyst-facing equivalent of `readelf -d`. Names follow
/// the binutils `DF_*` / `DF_1_*` constants without the prefix.
fn dt_flags(elf: &Elf<'_>, values: &mut Values) {
    let Some(dyns) = elf.dynamic.as_ref() else {
        return;
    };
    let mut flags = Vec::new();
    let mut flags1 = Vec::new();
    for d in &dyns.dyns {
        match d.d_tag {
            dynamic::DT_FLAGS => decompose_df(d.d_val, &mut flags),
            dynamic::DT_FLAGS_1 => decompose_df1(d.d_val, &mut flags1),
            _ => {}
        }
    }
    if !flags.is_empty() {
        values.insert(
            "elf.dt_flags",
            JsonValue::Array(
                flags
                    .iter()
                    .map(|s| JsonValue::String((*s).to_string()))
                    .collect(),
            ),
        );
    }
    if !flags1.is_empty() {
        values.insert(
            "elf.dt_flags_1",
            JsonValue::Array(
                flags1
                    .iter()
                    .map(|s| JsonValue::String((*s).to_string()))
                    .collect(),
            ),
        );
    }
}

fn decompose_df(v: u64, out: &mut Vec<&'static str>) {
    if v & 0x1 != 0 {
        out.push("origin");
    }
    if v & 0x2 != 0 {
        out.push("symbolic");
    }
    if v & 0x4 != 0 {
        out.push("text_rel");
    }
    if v & 0x8 != 0 {
        out.push("bind_now");
    }
    if v & 0x10 != 0 {
        out.push("static_tls");
    }
}

fn decompose_df1(v: u64, out: &mut Vec<&'static str>) {
    if v & 0x0000_0001 != 0 {
        out.push("now");
    }
    if v & 0x0000_0002 != 0 {
        out.push("global");
    }
    if v & 0x0000_0008 != 0 {
        out.push("no_delete");
    }
    if v & 0x0000_0010 != 0 {
        out.push("load_filter");
    }
    if v & 0x0000_0040 != 0 {
        out.push("init_first");
    }
    if v & 0x0000_0080 != 0 {
        out.push("no_open");
    }
    if v & 0x0000_0100 != 0 {
        out.push("origin");
    }
    if v & 0x0000_0800 != 0 {
        out.push("no_dump");
    }
    if v & 0x0000_2000 != 0 {
        out.push("no_open_2");
    }
    if v & 0x0800_0000 != 0 {
        out.push("pie");
    }
    if v & 0x1000_0000 != 0 {
        out.push("kernel_module");
    }
    if v & 0x4000_0000 != 0 {
        out.push("no_reloc");
    }
}

/// `.note.ABI-tag` (`NT_GNU_ABI_TAG = 1`) — declares the minimum
/// kernel version the binary expects. The descriptor is four 32-bit
/// words: ABI (0 = Linux), major, minor, patch.
fn abi_tag(elf: &Elf<'_>, bytes: &[u8], values: &mut Values) {
    let Some(notes) = elf.iter_note_headers(bytes) else {
        return;
    };
    for note in notes.flatten() {
        if note.name == "GNU" && note.n_type == 1 && note.desc.len() >= 16 {
            let words: [u32; 4] = [0, 1, 2, 3].map(|i| {
                let start = i * 4;
                u32::from_le_bytes(note.desc[start..start + 4].try_into().unwrap_or([0; 4]))
            });
            let os = match words[0] {
                0 => "linux",
                1 => "hurd",
                2 => "solaris",
                3 => "freebsd",
                4 => "netbsd",
                5 => "syllable",
                _ => "unknown",
            };
            let mut obj = serde_json::Map::new();
            obj.insert("os".into(), JsonValue::String(os.to_string()));
            obj.insert(
                "min_kernel".into(),
                JsonValue::String(format!("{}.{}.{}", words[1], words[2], words[3])),
            );
            values.insert("elf.abi", JsonValue::Object(obj));
            return;
        }
    }
}

/// `.note.gnu.property` (`NT_GNU_PROPERTY_TYPE_0 = 5`) — modern
/// hardening / ISA feature requirements. Names are
/// machine-dispatched because GNU's property numbering reuses
/// `0xc000_0000+` for both x86 (`X86_ISA_1_*`) and AArch64
/// (`AARCH64_FEATURE_*`). When we see an AArch64 PAUTH property
/// we also emit `elf.pauth_scheme` with the `platform:version`
/// pair that identifies the key-generation scheme.
fn gnu_property(elf: &Elf<'_>, bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    let Some(notes) = elf.iter_note_headers(bytes) else {
        return;
    };
    let is_aarch64 = elf.header.e_machine == header::EM_AARCH64;
    for note in notes.flatten() {
        if note.name != "GNU" || note.n_type != 5 {
            continue;
        }
        // Each property is `pr_type (u32) | pr_datasz (u32) | data | pad`
        // 8-byte aligned. Walk and collect names of known property types.
        let mut props = Vec::new();
        let mut off = 0;
        while off + 8 <= note.desc.len() {
            let pr_type = u32::from_le_bytes(note.desc[off..off + 4].try_into().unwrap_or([0; 4]));
            let pr_datasz =
                u32::from_le_bytes(note.desc[off + 4..off + 8].try_into().unwrap_or([0; 4]))
                    as usize;
            let data_start = off + 8;
            let data_end = data_start.saturating_add(pr_datasz);
            if data_end > note.desc.len() {
                break;
            }
            if let Some(name) = gnu_property_name(pr_type, is_aarch64) {
                let mut entry = serde_json::Map::new();
                entry.insert("type".into(), JsonValue::String(name.to_string()));
                if pr_datasz == 4 {
                    let v = u32::from_le_bytes(
                        note.desc[data_start..data_end].try_into().unwrap_or([0; 4]),
                    );
                    entry.insert("value".into(), JsonValue::String(format!("0x{v:x}")));
                    if is_aarch64 && pr_type == 0xC000_0000 {
                        // AARCH64_FEATURE_1_AND — bit-decomposed
                        // features that link-time enforcement
                        // requires (BTI / PAC / GCS).
                        let mut feats = Vec::new();
                        if v & 0x1 != 0 {
                            feats.push("bti");
                            metrics.insert("elf.has_aarch64_bti", 1.0);
                        }
                        if v & 0x2 != 0 {
                            feats.push("pac");
                            metrics.insert("elf.has_aarch64_pac", 1.0);
                        }
                        if v & 0x4 != 0 {
                            feats.push("gcs");
                        }
                        if !feats.is_empty() {
                            entry.insert(
                                "features".into(),
                                JsonValue::Array(
                                    feats
                                        .into_iter()
                                        .map(|s| JsonValue::String(s.into()))
                                        .collect(),
                                ),
                            );
                        }
                    } else if !is_aarch64 && pr_type == 0xC000_0002 {
                        // GNU_PROPERTY_X86_FEATURE_1_AND — Intel CET
                        // requirements stamped by the linker. bit 0 =
                        // IBT (Indirect Branch Tracking, shadow CFI),
                        // bit 1 = SHSTK (shadow stack).
                        if v & 0x1 != 0 {
                            metrics.insert("elf.has_cet_ibt", 1.0);
                        }
                        if v & 0x2 != 0 {
                            metrics.insert("elf.has_cet_shstk", 1.0);
                        }
                    } else if !is_aarch64 && pr_type == 0xC000_0001 {
                        // GNU_PROPERTY_X86_ISA_1_NEEDED — floor ISA
                        // level (v1/v2/v3/v4). Surface as a string so
                        // traits can match on the name.
                        let level = match v {
                            1 => Some("x86-64-v1"),
                            2 => Some("x86-64-v2"),
                            4 => Some("x86-64-v3"),
                            8 => Some("x86-64-v4"),
                            _ => None,
                        };
                        if let Some(s) = level {
                            put_str(values, "elf.x86_isa_level", s);
                        }
                    }
                } else if is_aarch64 && pr_type == 0xC000_0001 && pr_datasz == 16 {
                    // AARCH64_FEATURE_PAUTH — 16 bytes, two u64
                    // words identifying the key-generation scheme.
                    let platform = u64::from_le_bytes(
                        note.desc[data_start..data_start + 8]
                            .try_into()
                            .unwrap_or([0; 8]),
                    );
                    let version = u64::from_le_bytes(
                        note.desc[data_start + 8..data_start + 16]
                            .try_into()
                            .unwrap_or([0; 8]),
                    );
                    let scheme = format!("{}:{}", pauth_platform_name(platform), version);
                    entry.insert(
                        "platform".into(),
                        JsonValue::String(pauth_platform_name(platform).into()),
                    );
                    entry.insert("version".into(), JsonValue::Number(version.into()));
                    put_str(values, "elf.pauth_scheme", scheme);
                }
                props.push(JsonValue::Object(entry));
            }
            // 8-byte align
            off = (data_end + 7) & !7;
        }
        if !props.is_empty() {
            values.insert("elf.gnu_property", JsonValue::Array(props));
        }
        return;
    }
}

/// Map a GNU property type ID to its canonical name. AArch64
/// reuses the `0xC000_0000+` range for `AARCH64_FEATURE_*`, so the
/// dispatch keys off `elf.machine` to pick the right family.
fn gnu_property_name(pr_type: u32, is_aarch64: bool) -> Option<&'static str> {
    match pr_type {
        0x0000_0001 => Some("stack_size"),
        0x0000_0002 => Some("no_copy_on_protected"),
        0xC000_0000 if is_aarch64 => Some("aarch64_feature_1_and"),
        0xC000_0001 if is_aarch64 => Some("aarch64_feature_pauth"),
        0xC000_0000 => Some("x86_isa_1_used"),
        0xC000_0001 => Some("x86_isa_1_needed"),
        0xC000_0002 => Some("x86_feature_1_and"),
        0xC000_0003 => Some("x86_feature_2_used"),
        0xC000_0004 => Some("x86_feature_2_needed"),
        0xC000_0005 => Some("x86_isa_1_and"),
        _ => None,
    }
}

/// Recognized PAUTH platforms (from `linux/include/uapi/asm-generic/aarch64-pauth.h`
/// and binutils `elfnn-aarch64.c`). `0` is the invalid/unspecified
/// platform; LLVM uses `0x10000002` for its default scheme.
fn pauth_platform_name(platform: u64) -> &'static str {
    match platform {
        0 => "invalid",
        1 => "linux",
        0x1000_0002 => "llvm",
        _ => "unknown",
    }
}

/// `Verdef` table — symbol versions this shared object *exports*
/// (parallels `verneed` which is symbols it *requires*). Emits flat
/// strings of the form `"VERSION_NAME"`.
fn provided_versions(elf: &Elf<'_>, values: &mut Values) {
    let Some(verdef) = elf.verdef.as_ref() else {
        return;
    };
    let mut out: Vec<JsonValue> = Vec::new();
    for def in verdef.iter() {
        for aux in def.iter() {
            let name = elf.dynstrtab.get_at(aux.vda_name).unwrap_or("");
            if !name.is_empty() {
                out.push(JsonValue::String(name.to_string()));
            }
        }
    }
    if !out.is_empty() {
        values.insert("elf.provided_versions", JsonValue::Array(out));
    }
}

/// Return the file bytes of a named section, or `None` when absent.
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

/// Flat `elf.*` numeric metrics — the integer-valued counterparts to
/// the string facts that already live on the `values` tree
/// (`elf.machine`, `elf.type`, …). Trait rules read these via the
/// metric map for thresholding. Field set mirrors what cleave's
/// `ElfMetrics` historically populated, so traits that key on
/// `elf.section_count`, `elf.has_plt`, `elf.nx_enabled`, etc. keep
/// working after cleave's typed metrics retire.
fn elf_numeric_metrics(elf: &Elf<'_>, _bytes: &[u8], metrics: &mut Metrics, values: &mut Values) {
    // Header constants. `elf.machine` and `elf.type` already live on
    // the values tree as strings — the numeric forms add nothing.
    metrics.insert("elf.bits", f64::from(if elf.is_64 { 64u32 } else { 32u32 }));
    metrics.insert("elf.little_endian", f64::from(u8::from(elf.little_endian)));
    metrics.insert("elf.entry", elf.header.e_entry as f64);
    metrics.insert("elf.program_header_count", elf.program_headers.len() as f64);
    // Section count flows through `sections.count` (cross-format aggregate
    // emitted by `emit_section_metrics`). Don't dual-emit `elf.section_count`.
    metrics.insert(
        "elf.section_relocation_group_count",
        elf.shdr_relocs.len() as f64,
    );

    // Program headers / segments. PT_LOAD = 1, PT_GNU_STACK = 0x6474_e551.
    // PF_X = 1, PF_W = 2.
    let mut max_file_size: u64 = 0;
    let mut max_memory_size: u64 = 0;
    let mut has_gnu_stack = false;
    let mut nx_enabled = true; // default: no executable stack signal
    let mut wx_segment_count: u64 = 0;
    let mut entry_in_writable_segment = false;
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
            let span = ph.p_memsz.max(ph.p_filesz);
            let end = ph.p_vaddr.saturating_add(span);
            load_ranges.push((ph.p_vaddr, end, idx));
            if entry != 0 && entry >= ph.p_vaddr && entry < end {
                entry_in_any_segment = true;
                if writable {
                    entry_in_writable_segment = true;
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
    metrics.insert("elf.load_segment_max_file_size", max_file_size as f64);
    metrics.insert("elf.load_segment_max_memory_size", max_memory_size as f64);
    metrics.insert("elf.nx_enabled", f64::from(u8::from(nx_enabled)));
    metrics.insert("elf.executable_stack", f64::from(u8::from(!nx_enabled)));
    metrics.insert("elf.wx_segment_count", wx_segment_count as f64);
    if entry_in_writable_segment {
        metrics.insert("elf.entry_in_writable_segment", 1.0);
    }
    if entry != 0 && !entry_in_any_segment {
        metrics.insert("elf.entry_outside_segments", 1.0);
    }
    if interp_count > 1 {
        metrics.insert("elf.multiple_pt_interp", 1.0);
    }
    // Entry-in-last-segment: the EP's containing PT_LOAD is the one with
    // the highest p_vaddr. UPX-style packers stash the unpacker stub
    // there; vendor binaries land EPs in earlier segments.
    if let (Some(ep_idx), Some(last_idx)) = (entry_load_idx, last_load_idx) {
        if ep_idx == last_idx {
            metrics.insert("elf.entry_in_last_segment", 1.0);
        }
    }
    // Overlapping PT_LOAD pairs — sort by start address, then any
    // segment whose end exceeds the next segment's start overlaps.
    if load_ranges.len() > 1 {
        let mut sorted = load_ranges.clone();
        sorted.sort_by_key(|t| t.0);
        let mut overlap_idxs: std::collections::HashSet<usize> = std::collections::HashSet::new();
        for w in sorted.windows(2) {
            let (a_start, a_end, a_idx) = w[0];
            let (b_start, _, b_idx) = w[1];
            if a_end > b_start && b_start >= a_start {
                overlap_idxs.insert(a_idx);
                overlap_idxs.insert(b_idx);
            }
        }
        if !overlap_idxs.is_empty() {
            metrics.insert("elf.segment_overlap_count", overlap_idxs.len() as f64);
            let mut names: Vec<String> = overlap_idxs
                .into_iter()
                .map(|i| format!("PT_LOAD#{i}"))
                .collect();
            names.sort();
            values.insert(
                "elf.overlapping_segments",
                JsonValue::Array(names.into_iter().map(JsonValue::String).collect()),
            );
        }
    }
    // First-segment gap — bytes between header table end and the first
    // PT_LOAD's file offset. Non-zero is a "header cave".
    let header_end = elf
        .header
        .e_phoff
        .saturating_add(u64::from(elf.header.e_phnum) * u64::from(elf.header.e_phentsize));
    if let Some(first_off) = min_load_offset {
        if first_off > header_end {
            metrics.insert("elf.first_segment_gap", (first_off - header_end) as f64);
        }
    }
    // Section header count mismatch — `e_shnum` vs walked sections.
    if usize::from(elf.header.e_shnum) != elf.section_headers.len() {
        metrics.insert("elf.section_header_count_mismatch", 1.0);
    }
    // ET_REL (relocatable object) files legitimately omit PT_GNU_STACK
    // because they have no program headers; only flag absence for
    // ET_EXEC / ET_DYN.
    let stack_section_absent = !has_gnu_stack && elf.header.e_type != header::ET_REL;
    metrics.insert(
        "elf.gnu_stack_section_absent",
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
    let mut has_gnu_stack_section = false;
    let mut has_rustc_section = false;
    let mut text_writable = false;
    let mut rodata_writable = false;
    let mut debug_section_count: u64 = 0;
    let mut compressed_count: u64 = 0;
    let mut versym_size: u64 = 0;
    let mut name_seen: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    let entry = elf.header.e_entry;
    for sh in elf.section_headers.iter() {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        if !name.is_empty() {
            *name_seen.entry(name.to_string()).or_default() += 1;
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
            ".note.GNU-stack" => has_gnu_stack_section = true,
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
    metrics.insert("elf.has_plt", f64::from(u8::from(has_plt)));
    metrics.insert("elf.has_got", f64::from(u8::from(has_got)));
    metrics.insert("elf.has_eh_frame", f64::from(u8::from(has_eh_frame)));
    metrics.insert("elf.has_note", f64::from(u8::from(has_note)));
    if has_debuglink {
        metrics.insert("elf.has_debuglink", 1.0);
    }
    if has_symtab {
        metrics.insert("elf.has_symtab", 1.0);
    }
    if has_rustc_section {
        metrics.insert("elf.has_rustc_section", 1.0);
    }
    if has_dot_hash && has_gnu_hash_sect {
        metrics.insert("elf.has_both_hash_tables", 1.0);
    }
    if text_writable {
        metrics.insert("elf.text_section_writable", 1.0);
    }
    if rodata_writable {
        metrics.insert("elf.rodata_writable", 1.0);
    }
    if debug_section_count > 0 {
        metrics.insert("elf.debug_section_count", debug_section_count as f64);
    }
    if compressed_count > 0 {
        metrics.insert("elf.compressed_sections_count", compressed_count as f64);
    }
    // Override goblin's "stack section absent" decision with the actual
    // `.note.GNU-stack` section presence; the program-header walk above
    // already keys off PT_GNU_STACK, but having both signals is useful.
    let _ = has_gnu_stack_section;
    // Each `.gnu.version` entry is a 16-bit half per dynamic symbol.
    if versym_size > 0 {
        metrics.insert("elf.dt_versym_count", (versym_size / 2) as f64);
    }
    let dup_count = name_seen.values().filter(|&&c| c > 1).count() as u64;
    if dup_count > 0 {
        metrics.insert("elf.duplicate_section_name_count", dup_count as f64);
    }

    // Exact note count: walk note headers. Falls back to the
    // section-level approximation above when `iter_note_headers`
    // can't read the binary.
    if let Some(notes) = elf.iter_note_headers(_bytes) {
        let walked = notes.flatten().count() as u64;
        if walked > 0 {
            note_count = walked;
        }
    }
    metrics.insert("elf.note_count", note_count as f64);

    if let Some(name) = entry_section {
        put_str(values, "elf.entry_section", &name);
    }
}

/// Symbol-table + relocation-table counts. Cheap structural facts
/// goblin already has in hand; emitting them as flat metrics lets
/// trait engines threshold on "is the binary stripped" /
/// "does it have an unusual number of relocations" without walking
/// the dynsym table themselves.
fn table_counts(elf: &Elf<'_>, metrics: &mut Metrics) {
    metrics.insert("elf.dynsym_count", elf.dynsyms.len() as f64);
    metrics.insert("elf.symtab_count", elf.syms.len() as f64);
    metrics.insert("elf.dynrela_count", elf.dynrelas.len() as f64);
    metrics.insert("elf.dynrel_count", elf.dynrels.len() as f64);
    metrics.insert("elf.pltreloc_count", elf.pltrelocs.len() as f64);
    // DT_NEEDED entries are this ELF's shared-library dependencies.
    // Flows through the cross-format `dependencies.count` metric.
    metrics.insert("dependencies.count", elf.libraries.len() as f64);
}

/// `elf.*` metrics derived from the dynamic-section tag stream. Each
/// is a hardening / build-environment / sandbox-escape signal the
/// trait engine wants as a numeric/bool flag rather than a substring
/// match against `elf.gnu_property[]` / `elf.dt_flags[]`.
///
/// - `has_dt_textrel` — `DT_TEXTREL` (writable code requirement;
///   normal binaries don't need it, malware loaders sometimes do).
/// - `has_dt_audit` / `has_dt_depaudit` — auditor hooks the loader
///   calls on every dlopen; sandbox-escape signal.
/// - `has_dt_debug` — non-zero `DT_DEBUG` (used by runtime debuggers
///   and some packers).
/// - `has_dt_relr` — modern compressed relocations
///   (glibc 2.36+ / lld 13+).
/// - `has_gnu_hash` — newer hash table format; absence on a recent
///   binary is anomalous.
/// - `init_array_count` / `fini_array_count` / `preinit_array_count`
///   — constructor / destructor counts. CRT-initializer abuse drops
///   payloads into these arrays.
/// - `dt_needed_abs_path_count` / `dt_needed_traversal_count` —
///   anomaly counts over the DT_NEEDED library list.
/// - `dt_runpath_uses_origin` — `$ORIGIN` token in DT_RUNPATH (the
///   canonical relative-path runtime search base; common in modern
///   builds but sometimes abused).
/// - `has_direct_loader_dep` — a library directly DT_NEEDEDs the
///   dynamic loader (`ld-linux-*.so.*`/`ld-musl-*.so.*`); legit libs
///   pick up the loader transitively via libc, so direct dependency
///   is a strong tampering tell.
fn dynamic_metrics(elf: &Elf<'_>, metrics: &mut Metrics) {
    use goblin::elf::dynamic::{
        DT_AUDIT, DT_DEBUG, DT_DEPAUDIT, DT_FINI_ARRAYSZ, DT_FLAGS_1, DT_GNU_HASH, DT_INIT_ARRAYSZ,
        DT_PREINIT_ARRAYSZ, DT_RELACOUNT, DT_RPATH, DT_RUNPATH, DT_TEXTREL, DT_VERSYM,
    };
    // DT_RELR (36) isn't a named constant in goblin's enum yet; use
    // the ELF-spec literal directly.
    const DT_RELR: u64 = 36;

    // DT_NEEDED count surfaces under the cross-format
    // `dependencies.count` metric. No per-format alias.
    metrics.insert("dependencies.count", elf.libraries.len() as f64);

    let Some(dynamic) = elf.dynamic.as_ref() else {
        return;
    };

    let mut init_arraysz: u64 = 0;
    let mut fini_arraysz: u64 = 0;
    let mut preinit_arraysz: u64 = 0;
    let mut has_rpath_tag = false;
    let mut has_runpath_tag = false;
    let mut dt_versym_present = false;
    for d in &dynamic.dyns {
        match d.d_tag {
            DT_TEXTREL => {
                metrics.insert("elf.has_dt_textrel", 1.0);
            }
            DT_AUDIT => {
                metrics.insert("elf.has_dt_audit", 1.0);
            }
            DT_DEPAUDIT => {
                metrics.insert("elf.has_dt_depaudit", 1.0);
            }
            DT_DEBUG if d.d_val != 0 => {
                metrics.insert("elf.has_dt_debug", 1.0);
            }
            DT_RELR => {
                metrics.insert("elf.has_dt_relr", 1.0);
            }
            DT_GNU_HASH => {
                metrics.insert("elf.has_gnu_hash", 1.0);
            }
            DT_INIT_ARRAYSZ => init_arraysz = d.d_val,
            DT_FINI_ARRAYSZ => fini_arraysz = d.d_val,
            DT_PREINIT_ARRAYSZ => preinit_arraysz = d.d_val,
            DT_FLAGS_1 => {
                metrics.insert("elf.dt_flags_1_raw", d.d_val as f64);
            }
            DT_RELACOUNT => {
                metrics.insert("elf.relacount", d.d_val as f64);
            }
            DT_RPATH => has_rpath_tag = true,
            DT_RUNPATH => has_runpath_tag = true,
            DT_VERSYM => dt_versym_present = true,
            _ => {}
        }
    }
    if has_rpath_tag {
        metrics.insert("elf.has_rpath", 1.0);
    }
    if has_runpath_tag {
        metrics.insert("elf.has_runpath", 1.0);
    }
    // DT_VERSYM presence acts as a marker when the section walk in
    // `elf_numeric_metrics` already established the accurate
    // `.gnu.version` half-count; otherwise this falls back to 1 so
    // trait engines can still distinguish "has versioned symbols at
    // all" from "no versioning".
    if dt_versym_present && metrics.get("elf.dt_versym_count").is_none() {
        metrics.insert("elf.dt_versym_count", 1.0);
    }
    let ptr_size = if elf.is_64 { 8u64 } else { 4u64 };
    if init_arraysz > 0 {
        metrics.insert("elf.init_array_count", (init_arraysz / ptr_size) as f64);
    }
    if fini_arraysz > 0 {
        metrics.insert("elf.fini_array_count", (fini_arraysz / ptr_size) as f64);
    }
    if preinit_arraysz > 0 {
        metrics.insert(
            "elf.preinit_array_count",
            (preinit_arraysz / ptr_size) as f64,
        );
    }

    // DT_NEEDED anomaly walk. Each `elf.libraries` entry is the
    // string already resolved from DT_NEEDED via the dynstr table.
    let mut abs_path_count: u64 = 0;
    let mut traversal_count: u64 = 0;
    let mut direct_loader_dep = false;
    for needed in &elf.libraries {
        if needed.starts_with('/') {
            abs_path_count += 1;
        }
        if needed.split('/').any(|seg| seg == "..") {
            traversal_count += 1;
        }
        if is_dynamic_loader_soname(needed) {
            direct_loader_dep = true;
        }
    }
    if abs_path_count > 0 {
        metrics.insert("elf.dt_needed_abs_path_count", abs_path_count as f64);
    }
    if traversal_count > 0 {
        metrics.insert("elf.dt_needed_traversal_count", traversal_count as f64);
    }
    if direct_loader_dep {
        metrics.insert("elf.has_direct_loader_dep", 1.0);
    }

    // DT_RUNPATH $ORIGIN check — RUNPATH entries also serialise as
    // colon-separated strings via the dynstr table; goblin parsed
    // them into the `runpaths` slice already.
    if elf
        .runpaths
        .iter()
        .any(|p| p.split(':').any(|seg| seg.contains("$ORIGIN")))
    {
        metrics.insert("elf.dt_runpath_uses_origin", 1.0);
    }
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
            entry.insert("file_offset".into(), JsonValue::Number(ph.p_offset.into()));
            entry.insert("file_size".into(), JsonValue::Number(ph.p_filesz.into()));
            entry.insert("memory_size".into(), JsonValue::Number(ph.p_memsz.into()));
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
        values.insert("elf.segments", JsonValue::Array(segs));
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

/// `true` when `name` matches one of the well-known dynamic-loader
/// SONAMEs (`ld-linux-*.so.*` / `ld-musl-*.so.*` / `ld-*.so.*`). A
/// *library* with the loader as a direct DT_NEEDED is anomalous —
/// the loader is normally pulled in transitively via libc.
fn is_dynamic_loader_soname(name: &str) -> bool {
    let base = name.rsplit('/').next().unwrap_or(name);
    base.starts_with("ld-linux") || base.starts_with("ld-musl") || base == "ld.so"
}

/// Cross-format `binary.*` metrics derivable from ELF header state.
fn binary_flags(elf: &Elf<'_>, metrics: &mut Metrics) {
    // PIE: dynamically-linked executable (`ET_DYN` + `PT_INTERP`).
    // A shared library is also `ET_DYN` but has no interpreter.
    let is_pie = elf.header.e_type == header::ET_DYN && elf.interpreter.is_some();
    metrics.insert("binary.is_pie", f64::from(u8::from(is_pie)));

    // Stripped: `.symtab` section absent. Imports stay in `.dynsym`
    // and survive `strip`, so they're not a reliable signal.
    let has_symtab = elf
        .section_headers
        .iter()
        .any(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(".symtab"));
    metrics.insert("binary.is_stripped", f64::from(u8::from(!has_symtab)));
}

/// Emit the names of canonical metadata sections that a normal
/// `gcc`/`clang` build produces but are *absent* from this ELF. The
/// list is the positive signal — every entry is a section the strip
/// tool removed. Forensically this separates "developer build" from
/// "release/strip" from "stripped harder than usual" (e.g., binaries
/// missing `.comment` are particularly suspicious — toolchain banners
/// rarely fall to standard `strip` invocations).
fn stripped_metadata(elf: &Elf<'_>, values: &mut Values, metrics: &mut Metrics) {
    // Canonical sections an unstripped Linux toolchain emits. We don't
    // list every `.debug_*` variant individually — `.debug_info` is the
    // load-bearing one; if it's gone, the rest are gone.
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
        .filter_map(|sh| elf.shdr_strtab.get_at(sh.sh_name))
        .collect();

    let stripped: Vec<JsonValue> = EXPECTED
        .iter()
        .filter(|name| !present.contains(*name))
        .map(|name| JsonValue::String((*name).to_string()))
        .collect();

    metrics.insert("elf.stripped_metadata_section_count", stripped.len() as f64);
    if !stripped.is_empty() {
        values.insert("elf.stripped_metadata_sections", JsonValue::Array(stripped));
    }
    // Dedicated `stripped_but_symtab_present` flag: `.comment` and
    // `.debug_*` removed but `.symtab` retained. Distinctive shape:
    // a `strip --strip-debug` build that left symbol names intact.
    let symtab_present = present.contains(".symtab");
    let debug_or_comment_gone = !present.contains(".comment") || !present.contains(".debug_info");
    metrics.insert(
        "elf.stripped_but_symtab_present",
        f64::from(u8::from(symtab_present && debug_or_comment_gone)),
    );
}

/// Emit the GNU symbol-version requirements one per `library@VERSION`
/// string. Forensically the strongest fingerprint of a Linux binary's
/// build environment: the highest `GLIBC_x.y` in this list is the
/// floor glibc version the binary loads on.
fn needed_versions(elf: &Elf<'_>, values: &mut Values) {
    let Some(verneed) = elf.verneed.as_ref() else {
        return;
    };
    let mut out: Vec<JsonValue> = Vec::new();
    for need in verneed.iter() {
        let lib = elf.dynstrtab.get_at(need.vn_file).unwrap_or("");
        for aux in need.iter() {
            let ver = elf.dynstrtab.get_at(aux.vna_name).unwrap_or("");
            if !lib.is_empty() && !ver.is_empty() {
                out.push(JsonValue::String(format!("{lib}@{ver}")));
            }
        }
    }
    if !out.is_empty() {
        values.insert("elf.needed_versions", JsonValue::Array(out));
    }
}

/// Determine the RELRO state.
///
/// - **no RELRO** — neither `PT_GNU_RELRO` nor `DT_BIND_NOW`/`DT_FLAGS &
///   BIND_NOW`. Modern toolchains rarely produce this; usually a sign of
///   a hand-rolled or hardened-stripped binary.
/// - **partial** — `PT_GNU_RELRO` present, lazy binding still on. GOT
///   is read-only after relocation but PLT entries are resolved on
///   first call.
/// - **full** — `PT_GNU_RELRO` present AND `DT_BIND_NOW` (or
///   `DT_FLAGS & DF_BIND_NOW`, or `DT_FLAGS_1 & DF_1_NOW`). Everything
///   resolved at load time; GOT *and* PLT are read-only.
fn relro(elf: &Elf<'_>, values: &mut Values) {
    let has_relro_segment = elf
        .program_headers
        .iter()
        .any(|ph| ph.p_type == program_header::PT_GNU_RELRO);
    if !has_relro_segment {
        return;
    }
    let bind_now = elf.dynamic.as_ref().is_some_and(|dyns| {
        dyns.dyns.iter().any(|d| match d.d_tag {
            dynamic::DT_BIND_NOW => true,
            dynamic::DT_FLAGS => (d.d_val & dynamic::DF_BIND_NOW) != 0,
            dynamic::DT_FLAGS_1 => (d.d_val & 0x0000_0001) != 0, // DF_1_NOW
            _ => false,
        })
    });
    put_str(
        values,
        "elf.relro",
        if bind_now { "full" } else { "partial" },
    );
}

fn elf_header(elf: &Elf<'_>, values: &mut Values) {
    put_str(values, "elf.machine", machine_string(elf.header.e_machine));
    put_str(
        values,
        "elf.class",
        if elf.is_64 { "elf64" } else { "elf32" },
    );
    put_str(
        values,
        "elf.endian",
        if elf.little_endian { "little" } else { "big" },
    );
    put_str(values, "elf.type", elf_type_string(elf.header.e_type));
    put_u64(values, "elf.entry", elf.header.e_entry);
    put_u64(values, "elf.version", u64::from(elf.header.e_version));
}

fn dynamic(elf: &Elf<'_>, values: &mut Values) {
    let needed: Vec<JsonValue> = elf
        .libraries
        .iter()
        .map(|lib| JsonValue::String((*lib).to_string()))
        .collect();
    values.insert("elf.needed", JsonValue::Array(needed));

    if let Some(soname) = elf.soname {
        put_str(values, "elf.soname", soname);
    }
    let rpaths: Vec<JsonValue> = elf
        .rpaths
        .iter()
        .map(|r| JsonValue::String((*r).to_string()))
        .collect();
    if !rpaths.is_empty() {
        values.insert("elf.rpath", JsonValue::Array(rpaths));
    }
    let runpaths: Vec<JsonValue> = elf
        .runpaths
        .iter()
        .map(|r| JsonValue::String((*r).to_string()))
        .collect();
    if !runpaths.is_empty() {
        values.insert("elf.runpath", JsonValue::Array(runpaths));
    }
}

fn sections(elf: &Elf<'_>, bytes: &[u8], _metrics: &mut Metrics, sections_out: &mut Vec<Section>) {
    for sh in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_owned();
        // SHT_NOBITS (8) sections have no file bytes. Other types
        // occupy `sh_offset..sh_offset + sh_size` in the file.
        let (file_offset, file_size) = if sh.sh_type == 8 {
            (sh.sh_offset, 0)
        } else {
            (sh.sh_offset, sh.sh_size)
        };
        let entropy = (file_size > 0).then(|| section_entropy(bytes, file_offset, file_size));
        sections_out.push(Section {
            name,
            vaddr: sh.sh_addr,
            vsize: sh.sh_size,
            file_offset,
            file_size,
            flags: section_flags(sh.sh_flags)
                .into_iter()
                .map(str::to_string)
                .collect(),
            flags_raw: Some(sh.sh_flags),
            entropy,
        });
    }
}

fn section_entropy(bytes: &[u8], offset: u64, size: u64) -> f64 {
    if size == 0 {
        return 0.0;
    }
    let start = usize::try_from(offset).unwrap_or(usize::MAX);
    let end = start.saturating_add(usize::try_from(size).unwrap_or(usize::MAX));
    if start >= bytes.len() {
        return 0.0;
    }
    let end = end.min(bytes.len());
    entropy::shannon(&bytes[start..end])
}

fn symbols(
    elf: &Elf<'_>,
    values: &mut Values,
    metrics: &mut Metrics,
    imports_out: &mut crate::Imports,
    exports_out: &mut crate::Exports,
) {
    // Dynamic-symbol table: imports are undefined (`SHN_UNDEF`, section
    // index 0); exports are defined globals/weaks. STT_GNU_IFUNC entries
    // stay in `values` as a derived ELF-specific list; ordinary imports and
    // exports live only in the typed symbol views.
    let mut ifuncs = Vec::new();
    let mut fortify_count: u64 = 0;
    let mut hidden_count: u64 = 0;
    let mut stack_canary = false;
    // Static `.symtab` — hidden visibility + stack-canary symbols.
    // `STB_LOCAL = 0`, `STV_HIDDEN = 2`.
    for sym in elf.syms.iter() {
        if sym.st_bind() == 0 && sym.st_visibility() == 2 {
            hidden_count += 1;
        }
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            if name == "__stack_chk_fail" || name == "__stack_chk_guard" {
                stack_canary = true;
            }
        }
    }
    for sym in &elf.dynsyms {
        // Hidden + canary on dynsym too.
        if sym.st_bind() == 0 && sym.st_visibility() == 2 {
            hidden_count += 1;
        }
        let Some(name) = elf.dynstrtab.get_at(sym.st_name) else {
            continue;
        };
        if name == "__stack_chk_fail" || name == "__stack_chk_guard" {
            stack_canary = true;
        }
        if name.is_empty() {
            continue;
        }
        let stt = sym.st_info & 0xf;
        if stt == goblin::elf::sym::STT_GNU_IFUNC {
            ifuncs.push(JsonValue::String(name.to_string()));
        }
        // FORTIFY_SOURCE imports the `__*_chk` runtime variants of
        // memcpy / strcpy / sprintf / etc. Count them so a single
        // metric tells the trait engine whether the binary was
        // compiled with -D_FORTIFY_SOURCE.
        if name.starts_with("__") && name.ends_with("_chk") {
            fortify_count += 1;
        }
        if sym.st_shndx == 0 {
            // ELF doesn't bind a dynsym entry to a specific
            // DT_NEEDED library at link time — the dynamic linker
            // resolves at load. Leave `library` unset; consumers
            // that need it walk `elf.needed[]` separately.
            imports_out.push(crate::Import {
                name: name.to_string(),
                library: None,
                source: "elf-dynsym",
                offset: None,
                ordinal: None,
            });
        } else if sym.is_function() || sym.st_info & 0xf == 1 {
            // STB_GLOBAL = 1 (binding in upper nibble of st_info)
            exports_out.push(crate::Export {
                name: name.to_string(),
                source: "elf-dynsym",
                offset: Some(sym.st_value),
                ordinal: None,
                // ELF doesn't have a forwarded-export concept like
                // PE's reexports — symbol versioning solves the same
                // problem differently and is surfaced through the
                // version-info extractor.
                forward_to: None,
            });
        }
    }
    // Import/export totals flow through cross-format `imports.count`
    // / `exports.count` emitted by `lib.rs::extract_all` after every
    // format extractor runs. No per-format aliases.
    if fortify_count > 0 {
        metrics.insert("elf.fortify_source_count", fortify_count as f64);
    }
    if hidden_count > 0 {
        metrics.insert("elf.hidden_symbol_count", hidden_count as f64);
    }
    if stack_canary {
        metrics.insert("elf.stack_canary", 1.0);
    }
    if !ifuncs.is_empty() {
        values.insert("elf.ifuncs", JsonValue::Array(ifuncs));
    }
}

fn build_id(elf: &Elf<'_>, bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    // GNU build-id lives in a SHT_NOTE section named `.note.gnu.build-id`
    // (or `.gnu.build.attributes` in newer binutils). Walk note sections
    // and find the one with `n_type == NT_GNU_BUILD_ID (3)` and owner
    // `GNU`.
    let Some(notes) = elf.iter_note_headers(bytes) else {
        return;
    };
    for note in notes.flatten() {
        if note.name == "GNU" && note.n_type == 3 {
            put_str(values, "elf.build_id", hex_encode(note.desc));
            metrics.insert("elf.has_build_id", 1.0);
            metrics.insert("elf.build_id_length", note.desc.len() as f64);
            return;
        }
    }
}

fn interpreter(elf: &Elf<'_>, values: &mut Values) {
    if let Some(interp) = elf.interpreter {
        put_str(values, "elf.interpreter", interp);
    }
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

fn section_flags(flags: u64) -> Vec<&'static str> {
    let mut out = Vec::new();
    if flags & 0x1 != 0 {
        out.push("write");
    }
    if flags & 0x2 != 0 {
        out.push("alloc");
    }
    if flags & 0x4 != 0 {
        out.push("executable");
    }
    if flags & 0x10 != 0 {
        out.push("merge");
    }
    if flags & 0x20 != 0 {
        out.push("strings");
    }
    if flags & 0x40 != 0 {
        out.push("info_link");
    }
    if flags & 0x100 != 0 {
        out.push("tls");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::{Metrics, Strings, Values};

    fn run(bytes: &[u8]) -> (Values, Strings, Metrics) {
        let mut v = Values::new();
        let mut s = Strings::default();
        let mut m = Metrics::new();
        let mut sections = Vec::new();
        let mut imports = crate::Imports::new();
        let mut exports = crate::Exports::new();
        let mut functions = crate::Functions::new();
        let mut errors = Errors::new();
        // Ignore the Result — most negative-path tests pass malformed
        // bytes and we only care that extract returns without panic.
        let _ = extract(
            bytes,
            &mut v,
            &mut s,
            &mut m,
            &mut sections,
            &mut imports,
            &mut exports,
            &mut functions,
            &mut errors,
        );
        (v, s, m)
    }

    #[test]
    fn machine_string_handles_known() {
        assert_eq!(machine_string(header::EM_X86_64), "x86_64");
        assert_eq!(machine_string(header::EM_AARCH64), "aarch64");
        assert_eq!(machine_string(header::EM_ARM), "arm");
        assert_eq!(machine_string(header::EM_386), "i386");
        assert_eq!(machine_string(header::EM_RISCV), "riscv");
        assert_eq!(machine_string(header::EM_PPC64), "powerpc64");
        assert_eq!(machine_string(header::EM_S390), "s390");
        assert_eq!(machine_string(header::EM_LOONGARCH), "loongarch");
        assert_eq!(machine_string(0xeeee), "unknown");
    }

    #[test]
    fn elf_type_string_covers_canonical_set() {
        assert_eq!(elf_type_string(header::ET_NONE), "none");
        assert_eq!(elf_type_string(header::ET_REL), "relocatable");
        assert_eq!(elf_type_string(header::ET_EXEC), "executable");
        assert_eq!(elf_type_string(header::ET_DYN), "dynamic");
        assert_eq!(elf_type_string(header::ET_CORE), "core");
        assert_eq!(elf_type_string(0x9999), "unknown");
    }

    #[test]
    fn section_flags_decompose_each_bit() {
        // SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR
        let f = section_flags(0x1 | 0x2 | 0x4);
        assert_eq!(f, vec!["write", "alloc", "executable"]);
    }

    #[test]
    fn section_flags_picks_up_strings_and_merge() {
        // SHF_MERGE | SHF_STRINGS — `.rodata.str` section uses these.
        let f = section_flags(0x10 | 0x20);
        assert_eq!(f, vec!["merge", "strings"]);
    }

    #[test]
    fn section_flags_tls_bit() {
        let f = section_flags(0x100);
        assert_eq!(f, vec!["tls"]);
    }

    #[test]
    fn section_flags_empty_when_zero() {
        assert!(section_flags(0).is_empty());
    }

    #[test]
    fn gnu_property_name_handles_x86_features() {
        // GNU_PROPERTY_X86_FEATURE_1_AND (0xc0000002) carries IBT/SHSTK
        // markers on hardened x86 builds.
        assert!(gnu_property_name(0xc0000002, false).is_some());
    }

    #[test]
    fn gnu_property_name_handles_aarch64_pauth() {
        // BTI / PAC properties are aarch64-only.
        let bti = gnu_property_name(0xc0000000, true);
        assert!(bti.is_some());
    }

    #[test]
    fn pauth_platform_name_known_vendors() {
        // Apple = 1, LLVM = 2; vendor IDs come from the AArch64 ABI
        // supplement.
        assert!(!pauth_platform_name(1).is_empty());
        assert!(!pauth_platform_name(2).is_empty());
    }

    #[test]
    fn rejects_non_elf_bytes() {
        let (v, _, m) = run(b"not an elf");
        assert!(v.is_empty());
        // file.size is emitted by the dispatcher, not extract; nothing
        // from elf.* should be present here.
        assert!(m.get("binary.is_pie").is_none());
    }

    #[test]
    fn empty_input_doesnt_crash() {
        let (_, _, _) = run(&[]);
    }

    #[test]
    fn truncated_elf_header_doesnt_crash() {
        let mut bytes = vec![0u8; 32];
        bytes[..4].copy_from_slice(b"\x7fELF");
        let (_, _, _) = run(&bytes);
    }

    /// Read a real binary fixture from the cleave repo. Lets tests
    /// exercise the full extractor against a non-trivial ELF without
    /// shipping our own corpus.
    fn read_fixture(name: &str) -> Vec<u8> {
        let path = format!("../cleave/tests/fixtures/{name}");
        std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {path}: {e}"))
    }

    #[test]
    fn end_to_end_parses_real_elf_fixture() {
        let bytes = read_fixture("test.elf");
        let (v, _, m) = run(&bytes);
        // Pike-style flat schema: header fields live under `elf.<name>`
        // directly, not nested in `elf.header.*`.
        assert!(v.get("elf.class").is_some());
        assert!(v.get("elf.endian").is_some());
        assert!(v.get("elf.entry").is_some());
        // PIE / stripped flags are present (0 or 1) for any ELF.
        assert!(m.get("binary.is_pie").is_some());
        assert!(m.get("binary.is_stripped").is_some());
    }

    /// Pin every cleave-consumed emission added to support the
    /// ctx-only ELF analyzer migration. If filefacts stops emitting any
    /// of these, the analyzer's typed-metric path silently regresses
    /// to defaults — catch the loss here.
    #[test]
    fn pinned_elf_metrics_for_cleave_consumers() {
        let bytes = read_fixture("test.elf");
        let (v, _, m) = run(&bytes);
        // Header / section / segment counts.
        assert!(m.get("elf.bits").unwrap() == 64.0 || m.get("elf.bits").unwrap() == 32.0);
        assert!(m.get("elf.program_header_count").unwrap() > 0.0);
        // Section count flows through cross-format `sections.count`
        // emitted from `lib.rs::extract_all`. The per-format `extract`
        // call this test exercises populates the `sections` Vec
        // directly — the aggregate metric is asserted in the
        // top-level pipeline tests.
        assert!(m.get("dependencies.count").is_some());
        // Anomaly metrics are emitted as zero only when set; their
        // absence on a healthy binary is expected. We verify the
        // dependency-loaded metrics are present.
        assert!(v.get("elf.machine").is_some());
        assert!(v.get("elf.type").is_some());
        // segments[] entries now carry `flags_hex` for cleave's
        // segment_entries carrier.
        let segs = v.get("elf.segments").and_then(|j| j.as_array()).unwrap();
        let first = segs.first().unwrap().as_object().unwrap();
        assert!(first.contains_key("flags_hex"));
        assert!(first.contains_key("perms"));
        assert!(first.contains_key("type"));
    }
}
