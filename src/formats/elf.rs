//! ELF extractor.
//!
//! Reads Linux executables, shared libraries, and core dumps. Surfaces
//! the file header, dynamic-section facts (DT_NEEDED, RPATH, SONAME),
//! section table, dynamic symbol table imports/exports, and the
//! GNU build-id when present.

use crate::metric;
use crate::value_key;
use goblin::elf::note::{Note, NoteIterator};
use goblin::elf::{Elf, dynamic, header, program_header};
use serde_json::Value as JsonValue;

use crate::formats::common::bytes_at::{u32_le, u64_le};
use crate::formats::common::{
    NativeFormat, RizinTarget, XorScan, extract_binary_strings, extract_binary_strings_from_object,
    hex_encode, put_str, put_u64, rizin_fallback, section_entropy,
};
use crate::formats::goblin_safe;
use crate::output::{Errors, Metrics, Section, SectionFlag, Values};

/// Longest section name copied into the sections view, in chars.
const MAX_SECTION_NAME: usize = 256;

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
    // Wrap goblin parse in catch_unwind. ELF's dynamic-section
    // walker has panicked on malformed `DT_*` tables; `parse_elf`
    // turns a panic into a normal failure here. We record the
    // failure into the typed errors view and return Ok so the
    // byte-level metrics already in `metrics`/`strings` from the
    // generic pass survive.
    // Owns the header-patched copy when the section header table was cut
    // off; declared here so the parse borrowing it outlives the match.
    let detached;
    let elf = match goblin_safe::parse_elf(bytes) {
        goblin_safe::GoblinOutcome::Ok(elf) => elf,
        goblin_safe::GoblinOutcome::Failed(e) => {
            // A truncated file loses its trailing section header table first.
            // Parse the segment view instead of discarding the whole binary;
            // offsets are unchanged, so `bytes` stays authoritative below.
            detached = goblin_safe::elf_without_truncated_section_headers(bytes);
            if let Some(patched) = detached.as_deref()
                && let goblin_safe::GoblinOutcome::Ok(elf) = goblin_safe::parse_elf(patched)
            {
                errors_out.record_malformed(crate::Stage::ElfParse, e.to_string());
                metrics.insert(metric!("elf.section_headers_truncated"), 1.0);
                elf
            } else {
                extract_binary_strings(bytes, strings, XorScan::Yes);
                errors_out.record_malformed(crate::Stage::ElfParse, e.to_string());
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
    let segment_notes = drain_notes(elf.iter_note_headers(bytes), errors_out);

    elf_header(&elf, values);
    dynamic(&elf, values);
    sections(&elf, bytes, metrics, sections_out);
    *image_end = Some(image_end_of(&elf));
    symbols(&elf, values, metrics, symbols_out);
    build_id(&elf, bytes, &segment_notes, values, metrics, errors_out);
    interpreter(&elf, values);
    relro(&elf, values);
    needed_versions(&elf, values, errors_out);
    super::elf_dynamic::verdef(&elf, values, errors_out);
    super::elf_dynamic::init_arrays(&elf, bytes, values, metrics);
    super::elf_dynamic::dynsym_funcs(&elf, values);
    super::elf_syscalls::emit(&elf, bytes, values, metrics);
    stripped_metadata(&elf, values, metrics);
    comment(&elf, bytes, values, metrics);
    gcc_command_line(&elf, bytes, values);
    super::elf_dwarf::emit(&elf, bytes, values, metrics);
    dt_flags(&elf, values);
    abi_tag(&segment_notes, values);
    package_note(&segment_notes, values);
    gnu_property(&elf, &segment_notes, values, metrics);
    binary_flags(&elf, metrics);
    elf_numeric_metrics(&elf, &segment_notes, metrics, values);
    dynamic_metrics(&elf, metrics);
    table_counts(&elf, metrics);
    relocation_kinds(&elf, values);
    segments(&elf, values);
    section_headers(&elf, values);
    note_segment_coverage(&elf, bytes, metrics, errors_out);
    section_file_anomalies(&elf, bytes, metrics);
    rizin_fallback(
        RizinTarget {
            format: NativeFormat::Elf,
            bytes,
            strings,
            go_function_metadata: has_go_pclntab(&elf, bytes),
            settings: rizin,
        },
        sections_out,
        symbols_out,
        metrics,
    );
    linker_family(&elf, values);
    comment_fingerprint(values);
    super::elf_hashes::emit(&elf, values, symbols_out);
    super::upx::detect(bytes, values);
    {
        // VA→file-offset resolver: walk `PT_LOAD` program headers and
        // map any address in `[p_vaddr, p_vaddr + p_memsz)` to the
        // corresponding `[p_offset, p_offset + p_filesz)` byte. Used
        // by the old-format (Go <1.18) Go buildinfo decoder to chase
        // the version + modinfo pointers it stores instead of inline
        // strings.
        let loads: Vec<(u64, u64, u64, u64)> = elf
            .program_headers
            .iter()
            .filter(|p| p.p_type == goblin::elf::program_header::PT_LOAD)
            .map(|p| (p.p_vaddr, p.p_memsz, p.p_offset, p.p_filesz))
            .collect();
        let resolve = |va: u64| -> Option<usize> {
            for (vaddr, memsz, offset, filesz) in &loads {
                if va >= *vaddr && va < vaddr.saturating_add(*memsz) {
                    let delta = va - vaddr;
                    if delta >= *filesz {
                        return None;
                    }
                    return usize::try_from(offset.saturating_add(delta)).ok();
                }
            }
            None
        };
        let go_sections = super::go_buildinfo::GoSections {
            buildid_note: read_section(&elf, bytes, ".note.go.buildid"),
            pclntab: read_section(&elf, bytes, ".gopclntab"),
            rodata: read_section(&elf, bytes, ".rodata"),
        };
        super::go_buildinfo::detect(
            bytes,
            values,
            value_key!("elf.go"),
            Some(&resolve),
            &go_sections,
        );
    }
    super::build_toolchain::from_elf(values, sections_out, bytes);
}

/// Identify the linker family that produced this binary. Prefers the
/// dedicated `.note.*` sections (canonical, written by the linker
/// itself); falls back to scanning `.comment[]` banners for the
/// linker's name. Emits a single `elf.linker_family` string.
fn linker_family(elf: &Elf<'_>, values: &mut Values) {
    let by_section = |name: &str| {
        elf.section_headers
            .iter()
            .any(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(name))
    };
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
    let Some(entries) = values
        .get_key(value_key!("elf.comment"))
        .and_then(serde_json::Value::as_array)
        .cloned()
    else {
        return;
    };
    for entry in entries {
        let Some(text) = entry.as_str() else {
            continue;
        };
        let lower = text.to_lowercase();
        let family = if text.contains("GNU gold") {
            "gold"
        } else if text.contains("LLD") || lower.contains("ld.lld") || lower.contains("lld ") {
            "lld"
        } else if lower.contains("mold ") || text.contains("mold") {
            "mold"
        } else if text.contains("GNU ld") {
            "ld"
        } else {
            continue;
        };
        put_str(values, value_key!("elf.linker_family"), family);
        return;
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
    let Some(entries) = values
        .get_key(value_key!("elf.comment"))
        .and_then(serde_json::Value::as_array)
        .cloned()
    else {
        return;
    };
    let joined: String = entries
        .iter()
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
        values.insert_key(
            value_key!("elf.dt_flags"),
            JsonValue::Array(
                flags
                    .iter()
                    .map(|s| JsonValue::String((*s).to_string()))
                    .collect(),
            ),
        );
    }
    if !flags1.is_empty() {
        values.insert_key(
            value_key!("elf.dt_flags_1"),
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

/// `.note.package` (`n_type = 0xCAFE1A7E`, vendor `"FDO"`) — FDO
/// Package Metadata. The descriptor is a JSON document with a fixed
/// schema (<https://systemd.io/COREDUMP_PACKAGE_METADATA/>): `name`,
/// `version`, `type` (`rpm`/`deb`/`apk`/…), `cpe`, `url`, `vcs`.
/// Strongest distro/package attestation any binary format offers —
/// Wolfi, Chainguard, Fedora 36+, recent systemd builds emit it.
/// Surfaced as the `elf.package` subtree with the JSON keys verbatim
/// (so trait authors write `elf.package.type == "apk"`).
fn package_note(notes: &[Note<'_>], values: &mut Values) {
    for note in notes {
        if note.n_type != 0xCAFE_1A7E {
            continue;
        }
        // Trim trailing NULs — the section may pad up to 4 bytes.
        let Some(desc) = note.desc.split(|&b| b == 0).next() else {
            continue;
        };
        let Ok(text) = std::str::from_utf8(desc) else {
            continue;
        };
        let Ok(json) = serde_json::from_str::<JsonValue>(text) else {
            continue;
        };
        if json.is_null() {
            continue;
        }
        values.insert_key(value_key!("elf.package"), json);
        return;
    }
}

/// `.note.ABI-tag` (`NT_GNU_ABI_TAG = 1`) — declares the minimum
/// kernel version the binary expects. The descriptor is four 32-bit
/// words: ABI (0 = Linux), major, minor, patch.
fn abi_tag(notes: &[Note<'_>], values: &mut Values) {
    for note in notes {
        if note.name == "GNU" && note.n_type == 1 && note.desc.len() >= 16 {
            let words: [u32; 4] = [0, 1, 2, 3].map(|i| u32_le(note.desc, i * 4).unwrap_or(0));
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
            values.insert_key(value_key!("elf.abi"), JsonValue::Object(obj));
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
fn gnu_property(elf: &Elf<'_>, notes: &[Note<'_>], values: &mut Values, metrics: &mut Metrics) {
    let is_aarch64 = elf.header.e_machine == header::EM_AARCH64;
    for note in notes {
        if note.name != "GNU" || note.n_type != 5 {
            continue;
        }
        // Each property is `pr_type (u32) | pr_datasz (u32) | data | pad`
        // 8-byte aligned. Walk and collect names of known property types.
        let mut props = Vec::new();
        let mut off = 0;
        while off + 8 <= note.desc.len() {
            let pr_type = u32_le(note.desc, off).unwrap_or(0);
            let pr_datasz = u32_le(note.desc, off + 4).unwrap_or(0) as usize;
            let data_start = off + 8;
            let data_end = data_start.saturating_add(pr_datasz);
            if data_end > note.desc.len() {
                break;
            }
            if let Some(name) = gnu_property_name(pr_type, is_aarch64) {
                let mut entry = serde_json::Map::new();
                entry.insert("type".into(), JsonValue::String(name.to_string()));
                if pr_datasz == 4 {
                    let v = u32_le(note.desc, data_start).unwrap_or(0);
                    entry.insert("value".into(), JsonValue::String(format!("0x{v:x}")));
                    if is_aarch64 && pr_type == 0xC000_0000 {
                        // AARCH64_FEATURE_1_AND — bit-decomposed
                        // features that link-time enforcement
                        // requires (BTI / PAC / GCS).
                        let mut feats = Vec::new();
                        if v & 0x1 != 0 {
                            feats.push("bti");
                            metrics.insert(metric!("elf.has_aarch64_bti"), 1.0);
                        }
                        if v & 0x2 != 0 {
                            feats.push("pac");
                            metrics.insert(metric!("elf.has_aarch64_pac"), 1.0);
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
                            metrics.insert(metric!("elf.has_cet_ibt"), 1.0);
                        }
                        if v & 0x2 != 0 {
                            metrics.insert(metric!("elf.has_cet_shstk"), 1.0);
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
                            put_str(values, value_key!("elf.x86_isa_level"), s);
                        }
                    }
                } else if is_aarch64 && pr_type == 0xC000_0001 && pr_datasz == 16 {
                    // AARCH64_FEATURE_PAUTH — 16 bytes, two u64
                    // words identifying the key-generation scheme.
                    let platform = u64_le(note.desc, data_start).unwrap_or(0);
                    let version = u64_le(note.desc, data_start + 8).unwrap_or(0);
                    let scheme = format!("{}:{}", pauth_platform_name(platform), version);
                    entry.insert(
                        "platform".into(),
                        JsonValue::String(pauth_platform_name(platform).into()),
                    );
                    entry.insert("version".into(), JsonValue::Number(version.into()));
                    put_str(values, value_key!("elf.pauth_scheme"), scheme);
                }
                props.push(JsonValue::Object(entry));
            }
            // 8-byte align
            off = (data_end + 7) & !7;
        }
        if !props.is_empty() {
            values.insert_key(value_key!("elf.gnu_property"), JsonValue::Array(props));
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

/// Cheap Go probe: read the already-parsed `.gopclntab` section (no extra
/// parse) and validate its magic. False negatives are safe (fall back to deep
/// analysis); a false positive is impossible — no non-Go format writes a
/// pclntab magic — so this only ever picks the faster path for genuine Go.
fn has_go_pclntab(elf: &Elf<'_>, bytes: &[u8]) -> bool {
    read_section(elf, bytes, ".gopclntab").is_some_and(super::go_buildinfo::has_pclntab_magic)
}

/// The file bytes of the first section named `name`; `None` when there is no
/// such section or its header points past the file. Shared by the ELF
/// extractors (`elf_dwarf` reads its `.debug_*` sections through it).
pub(super) fn read_section<'a>(elf: &Elf<'_>, bytes: &'a [u8], name: &str) -> Option<&'a [u8]> {
    let sh = elf
        .section_headers
        .iter()
        .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(name))?;
    let start = usize::try_from(sh.sh_offset).ok()?;
    let len = usize::try_from(sh.sh_size).ok()?;
    let end = start.checked_add(len)?;
    bytes.get(start..end)
}

/// Flat `elf.*` numeric metrics — the integer-valued counterparts to
/// the string facts that already live on the `values` tree
/// (`elf.machine`, `elf.type`, …). Trait rules read these via the
/// metric map for thresholding. Field set mirrors what cleave's
/// `ElfMetrics` historically populated, so traits that key on
/// `elf.section_count`, `elf.has_plt`, `elf.nx_enabled`, etc. keep
/// working after cleave's typed metrics retire.
fn elf_numeric_metrics(
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
    // Overlapping PT_LOAD pairs — sort by start address, then any
    // segment whose end exceeds the next segment's start overlaps.
    if load_ranges.len() > 1 {
        let mut sorted = load_ranges;
        sorted.sort_by_key(|t| t.0);
        let mut overlap_idxs: std::collections::HashSet<usize> = std::collections::HashSet::new();
        for w in sorted.windows(2) {
            let &[(a_start, a_end, a_idx), (b_start, _, b_idx)] = w else {
                continue;
            };
            if a_end > b_start && b_start >= a_start {
                overlap_idxs.insert(a_idx);
                overlap_idxs.insert(b_idx);
            }
        }
        if !overlap_idxs.is_empty() {
            metrics.insert(
                metric!("elf.segment_overlap_count"),
                overlap_idxs.len() as f64,
            );
            let mut names: Vec<String> = overlap_idxs
                .into_iter()
                .map(|i| format!("PT_LOAD#{i}"))
                .collect();
            names.sort();
            values.insert_key(
                value_key!("elf.overlapping_segments"),
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
fn table_counts(elf: &Elf<'_>, metrics: &mut Metrics) {
    metrics.insert(metric!("elf.dynsym_count"), elf.dynsyms.len() as f64);
    metrics.insert(metric!("elf.symtab_count"), elf.syms.len() as f64);
    metrics.insert(metric!("elf.dynrela_count"), elf.dynrelas.len() as f64);
    metrics.insert(metric!("elf.dynrel_count"), elf.dynrels.len() as f64);
    metrics.insert(metric!("elf.pltreloc_count"), elf.pltrelocs.len() as f64);
    // DT_NEEDED entries are this ELF's shared-library dependencies.
    // Flows through the cross-format `dependencies.count` metric.
    metrics.insert(metric!("dependencies.count"), elf.libraries.len() as f64);
}

/// Aggregate per-relocation-type counts across `.rela.dyn` /
/// `.rel.dyn` / `.rela.plt`. The distribution is a useful
/// fingerprint:
///
/// - `R_*_RELATIVE` dominance signals a PIE / shared object
///   resolving load-time fixups.
/// - `R_*_JUMP_SLOT` count tracks the PLT entry count (one per
///   resolved import).
/// - `R_*_COPY` entries indicate the binary needs writable copies
///   of imported `.data` symbols (rare; almost always C++/glibc).
/// - `R_*_IRELATIVE` entries point at `STT_GNU_IFUNC` resolvers —
///   the runtime dispatcher mechanism used by both glibc internal
///   string-function dispatch and a small fraction of malware
///   loaders.
///
/// Names use the canonical binutils mnemonic per architecture.
/// Unrecognised codes fall through to `R_<MACHINE>_<NUM>`.
fn relocation_kinds(elf: &Elf<'_>, values: &mut Values) {
    let machine = elf.header.e_machine;
    let mut counts: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    let mut tally = |r_type: u32| {
        let name = relocation_kind_name(machine, r_type);
        *counts.entry(name).or_insert(0) += 1;
    };
    for r in &elf.dynrelas {
        tally(r.r_type);
    }
    for r in &elf.dynrels {
        tally(r.r_type);
    }
    for r in &elf.pltrelocs {
        tally(r.r_type);
    }
    if counts.is_empty() {
        return;
    }
    let mut obj = serde_json::Map::new();
    for (name, count) in counts {
        obj.insert(name, JsonValue::Number(count.into()));
    }
    values.insert_key(value_key!("elf.relocation_kinds"), JsonValue::Object(obj));
}

/// Per-machine relocation-type mnemonic. Returns the binutils name
/// (`R_X86_64_RELATIVE`, `R_AARCH64_JUMP_SLOT`, …) for the codes
/// most commonly seen in dynamic relocation tables; falls back to a
/// `R_<MACHINE>_<NUM>` string for codes the histogram doesn't cover
/// so unusual values still show up in the output.
fn relocation_kind_name(machine: u16, r_type: u32) -> String {
    let known = match machine {
        header::EM_X86_64 => match r_type {
            0 => Some("R_X86_64_NONE"),
            1 => Some("R_X86_64_64"),
            2 => Some("R_X86_64_PC32"),
            5 => Some("R_X86_64_COPY"),
            6 => Some("R_X86_64_GLOB_DAT"),
            7 => Some("R_X86_64_JUMP_SLOT"),
            8 => Some("R_X86_64_RELATIVE"),
            9 => Some("R_X86_64_GOTPCREL"),
            37 => Some("R_X86_64_IRELATIVE"),
            _ => None,
        },
        header::EM_AARCH64 => match r_type {
            0 => Some("R_AARCH64_NONE"),
            257 => Some("R_AARCH64_ABS64"),
            1024 => Some("R_AARCH64_COPY"),
            1025 => Some("R_AARCH64_GLOB_DAT"),
            1026 => Some("R_AARCH64_JUMP_SLOT"),
            1027 => Some("R_AARCH64_RELATIVE"),
            1042 => Some("R_AARCH64_IRELATIVE"),
            _ => None,
        },
        header::EM_ARM => match r_type {
            0 => Some("R_ARM_NONE"),
            2 => Some("R_ARM_ABS32"),
            18 => Some("R_ARM_COPY"),
            20 => Some("R_ARM_GLOB_DAT"),
            21 => Some("R_ARM_JUMP_SLOT"),
            23 => Some("R_ARM_RELATIVE"),
            160 => Some("R_ARM_IRELATIVE"),
            _ => None,
        },
        header::EM_386 => match r_type {
            0 => Some("R_386_NONE"),
            1 => Some("R_386_32"),
            5 => Some("R_386_COPY"),
            6 => Some("R_386_GLOB_DAT"),
            7 => Some("R_386_JUMP_SLOT"),
            8 => Some("R_386_RELATIVE"),
            42 => Some("R_386_IRELATIVE"),
            _ => None,
        },
        _ => None,
    };
    match known {
        Some(name) => name.to_string(),
        None => format!(
            "R_{}_{r_type}",
            machine_string(machine).to_ascii_uppercase()
        ),
    }
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
/// - `has_direct_loader_dependency` — a library directly DT_NEEDEDs the
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
    metrics.insert(metric!("dependencies.count"), elf.libraries.len() as f64);

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
                metrics.insert(metric!("elf.has_dt_textrel"), 1.0);
            }
            DT_AUDIT => {
                metrics.insert(metric!("elf.has_dt_audit"), 1.0);
            }
            DT_DEPAUDIT => {
                metrics.insert(metric!("elf.has_dt_depaudit"), 1.0);
            }
            DT_DEBUG if d.d_val != 0 => {
                metrics.insert(metric!("elf.has_dt_debug"), 1.0);
            }
            DT_RELR => {
                metrics.insert(metric!("elf.has_dt_relr"), 1.0);
            }
            DT_GNU_HASH => {
                metrics.insert(metric!("elf.has_gnu_hash"), 1.0);
            }
            DT_INIT_ARRAYSZ => init_arraysz = d.d_val,
            DT_FINI_ARRAYSZ => fini_arraysz = d.d_val,
            DT_PREINIT_ARRAYSZ => preinit_arraysz = d.d_val,
            DT_FLAGS_1 => {
                metrics.insert(metric!("elf.dt_flags_1_raw"), d.d_val as f64);
            }
            DT_RELACOUNT => {
                metrics.insert(metric!("elf.relacount"), d.d_val as f64);
            }
            DT_RPATH => has_rpath_tag = true,
            DT_RUNPATH => has_runpath_tag = true,
            DT_VERSYM => dt_versym_present = true,
            _ => {}
        }
    }
    if has_rpath_tag {
        metrics.insert(metric!("elf.has_rpath"), 1.0);
    }
    if has_runpath_tag {
        metrics.insert(metric!("elf.has_runpath"), 1.0);
    }
    // DT_VERSYM presence acts as a marker when the section walk in
    // `elf_numeric_metrics` already established the accurate
    // `.gnu.version` half-count; otherwise this falls back to 1 so
    // trait engines can still distinguish "has versioned symbols at
    // all" from "no versioning".
    if dt_versym_present && metrics.get("elf.dt_versym_count").is_none() {
        metrics.insert(metric!("elf.dt_versym_count"), 1.0);
    }
    let ptr_size = if elf.is_64 { 8u64 } else { 4u64 };
    if init_arraysz > 0 {
        metrics.insert(
            metric!("elf.init_array_count"),
            (init_arraysz / ptr_size) as f64,
        );
    }
    if fini_arraysz > 0 {
        metrics.insert(
            metric!("elf.fini_array_count"),
            (fini_arraysz / ptr_size) as f64,
        );
    }
    if preinit_arraysz > 0 {
        metrics.insert(
            metric!("elf.preinit_array_count"),
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
        metrics.insert(
            metric!("elf.dt_needed_abs_path_count"),
            abs_path_count as f64,
        );
    }
    if traversal_count > 0 {
        metrics.insert(
            metric!("elf.dt_needed_traversal_count"),
            traversal_count as f64,
        );
    }
    if direct_loader_dep {
        metrics.insert(metric!("elf.has_direct_loader_dependency"), 1.0);
    }

    // DT_RUNPATH $ORIGIN check — RUNPATH entries also serialise as
    // colon-separated strings via the dynstr table; goblin parsed
    // them into the `runpaths` slice already.
    if elf
        .runpaths
        .iter()
        .any(|p| p.split(':').any(|seg| seg.contains("$ORIGIN")))
    {
        metrics.insert(metric!("elf.dt_runpath_uses_origin"), 1.0);
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
            let full = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            let name = match full.char_indices().nth(MAX_SECTION_NAME) {
                Some((end, _)) => &full[..end],
                None => full,
            };
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
    metrics.insert(metric!("binary.is_pie"), f64::from(u8::from(is_pie)));

    // Stripped: `.symtab` section absent. Imports stay in `.dynsym`
    // and survive `strip`, so they're not a reliable signal.
    let has_symtab = elf
        .section_headers
        .iter()
        .any(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(".symtab"));
    metrics.insert(
        metric!("binary.is_stripped"),
        f64::from(u8::from(!has_symtab)),
    );
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

    metrics.insert(
        metric!("elf.stripped_metadata_section_count"),
        stripped.len() as f64,
    );
    if !stripped.is_empty() {
        values.insert_key(
            value_key!("elf.stripped_metadata_sections"),
            JsonValue::Array(stripped),
        );
    }
    // Dedicated `stripped_but_symtab_present` flag: `.comment` and
    // `.debug_*` removed but `.symtab` retained. Distinctive shape:
    // a `strip --strip-debug` build that left symbol names intact.
    let symtab_present = present.contains(".symtab");
    let debug_or_comment_gone = !present.contains(".comment") || !present.contains(".debug_info");
    metrics.insert(
        metric!("elf.stripped_with_symtab"),
        f64::from(u8::from(symtab_present && debug_or_comment_gone)),
    );
}

/// Emit the GNU symbol-version requirements one per `library@VERSION`
/// string. Forensically the strongest fingerprint of a Linux binary's
/// build environment: the highest `GLIBC_x.y` in this list is the
/// floor glibc version the binary loads on.
fn needed_versions(elf: &Elf<'_>, values: &mut Values, errors_out: &mut Errors) {
    let Some(verneed) = elf.verneed.as_ref() else {
        return;
    };
    let mut out: Vec<JsonValue> = Vec::new();
    // Both levels are lazy walks along file-controlled `vn_next` / `vna_next`
    // links.
    for need in goblin_safe::drain_or_record(verneed.iter(), errors_out, crate::Stage::ElfParse) {
        let lib = elf.dynstrtab.get_at(need.vn_file).unwrap_or("");
        for aux in goblin_safe::drain_or_record(need.iter(), errors_out, crate::Stage::ElfParse) {
            let ver = elf.dynstrtab.get_at(aux.vna_name).unwrap_or("");
            if !lib.is_empty() && !ver.is_empty() {
                out.push(JsonValue::String(format!("{lib}@{ver}")));
            }
        }
    }
    if !out.is_empty() {
        values.insert_key(value_key!("elf.needed_versions"), JsonValue::Array(out));
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
        value_key!("elf.relro"),
        if bind_now { "full" } else { "partial" },
    );
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
    // tell that was previously invisible. `e_phoff`, the per-entry sizes,
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

fn dynamic(elf: &Elf<'_>, values: &mut Values) {
    let needed: Vec<JsonValue> = elf
        .libraries
        .iter()
        .map(|lib| JsonValue::String((*lib).to_string()))
        .collect();
    values.insert_key(value_key!("elf.needed"), JsonValue::Array(needed));

    if let Some(soname) = elf.soname {
        put_str(values, value_key!("elf.soname"), soname);
    }
    let rpaths: Vec<JsonValue> = elf
        .rpaths
        .iter()
        .map(|r| JsonValue::String((*r).to_string()))
        .collect();
    if !rpaths.is_empty() {
        values.insert_key(value_key!("elf.rpath"), JsonValue::Array(rpaths));
    }
    let runpaths: Vec<JsonValue> = elf
        .runpaths
        .iter()
        .map(|r| JsonValue::String((*r).to_string()))
        .collect();
    if !runpaths.is_empty() {
        values.insert_key(value_key!("elf.runpath"), JsonValue::Array(runpaths));
    }
}

fn sections(elf: &Elf<'_>, bytes: &[u8], _metrics: &mut Metrics, sections_out: &mut Vec<Section>) {
    // Entropy is O(section length) and section ranges are attacker-supplied:
    // nothing requires them to be disjoint, so `e_shnum` headers can all cover
    // the same megabytes and cost `e_shnum × filesize` — measured at 11.8 s for
    // 2000 headers over one 8 MB range. An honest ELF's file-backed sections are
    // disjoint slices of the file, so its own length is the exact budget they
    // need and this never bites a real binary.
    let mut entropy_budget = bytes.len() as u64;
    for sh in &elf.section_headers {
        // Truncate by chars so the cut always lands on a boundary. The string
        // table is attacker-supplied: `sh_name` may point into a run holding no
        // NUL, making a section's "name" the rest of the file. Measured without
        // this cap, an 8.5 MB ELF whose four section names each ran to EOF
        // emitted 201 MB of JSON (control bytes escape to ``, 6x), and
        // the 2000-section version did not finish. Real names are a handful of
        // bytes, so nothing legitimate reaches this.
        let full = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        let name = match full.char_indices().nth(MAX_SECTION_NAME) {
            Some((end, _)) => &full[..end],
            None => full,
        };
        let name = name.to_owned();
        // SHT_NOBITS (8) sections have no file bytes. Other types
        // occupy `sh_offset..sh_offset + sh_size` in the file.
        let (file_offset, file_size) = if sh.sh_type == 8 {
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

/// Map a virtual address to a file offset through the `PT_LOAD` segments.
///
/// This is the only VA→offset path that survives section-header stripping:
/// release and packed binaries (and many shipped inside wheels) routinely drop
/// the section table while keeping the loadable segments the dynamic linker
/// needs. Returns `None` when no `PT_LOAD` segment covers `va` in the file image
/// (e.g. a `.bss`-only address with no file backing).
fn load_segment_va_to_offset(elf: &Elf<'_>, va: u64) -> Option<u64> {
    elf.program_headers
        .iter()
        .filter(|p| p.p_type == goblin::elf::program_header::PT_LOAD)
        .find_map(|p| {
            let delta = va.checked_sub(p.p_vaddr)?;
            (delta < p.p_filesz).then(|| p.p_offset.saturating_add(delta))
        })
}

fn symbols(
    elf: &Elf<'_>,
    values: &mut Values,
    metrics: &mut Metrics,
    symbols_out: &mut crate::Symbols,
) {
    // Dynamic-symbol table: imports are undefined (`SHN_UNDEF`, section
    // index 0); exports are defined globals/weaks. STT_GNU_IFUNC entries
    // stay in `values` as a derived ELF-specific list; ordinary imports and
    // exports live only in the typed symbol views.
    let mut ifuncs = Vec::new();
    let mut fortify_count: u64 = 0;
    let mut hidden_count: u64 = 0;
    let mut stack_canary = false;
    // Aggregate symbol-type / binding / visibility histograms across
    // `.symtab` and `.dynsym`. The forensic value is in the *ratio*
    // (Go binaries skew heavily toward STT_FUNC; C++ STL templates
    // generate huge STT_OBJECT counts; rootkits often have many
    // STT_TLS to hide state) so we surface the counts under
    // `elf.symbol_kinds` rather than as individual metrics.
    let mut sym_type_counts: [u64; 16] = [0; 16];
    let mut sym_bind_counts: [u64; 4] = [0; 4];
    let mut sym_vis_counts: [u64; 4] = [0; 4];
    // Static `.symtab` — hidden visibility + stack-canary symbols.
    // `STB_LOCAL = 0`, `STV_HIDDEN = 2`.
    for sym in elf.syms.iter() {
        if sym.st_bind() == 0 && sym.st_visibility() == 2 {
            hidden_count += 1;
        }
        tally_symbol_kinds(
            sym,
            &mut sym_type_counts,
            &mut sym_bind_counts,
            &mut sym_vis_counts,
        );
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            if name == "__stack_chk_fail" || name == "__stack_chk_guard" {
                stack_canary = true;
            }
        }
    }
    // File offset of the `.dynstr` table, so each dynamic symbol's name can be
    // located in the file (`dynstr_offset + st_name`). ELF binds no useful
    // offset to an import-table *entry*, but the name string itself is a real,
    // anchorable location — what consumers want to point at.
    //
    // Prefer the `.dynstr` section header, but fall back to the dynamic
    // segment's `DT_STRTAB` (a virtual address resolved back to a file offset
    // through `PT_LOAD`) when the section table is absent. Release and packed
    // binaries strip section headers entirely while keeping the dynamic symbols
    // fully resolvable, so the section-only lookup would otherwise leave every
    // import name unanchored.
    let dynstr_offset = elf
        .section_headers
        .iter()
        .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(".dynstr"))
        .map(|sh| sh.sh_offset)
        .or_else(|| load_segment_va_to_offset(elf, elf.dynamic.as_ref()?.info.strtab as u64));
    for sym in &elf.dynsyms {
        // Hidden + canary on dynsym too.
        if sym.st_bind() == 0 && sym.st_visibility() == 2 {
            hidden_count += 1;
        }
        tally_symbol_kinds(
            sym,
            &mut sym_type_counts,
            &mut sym_bind_counts,
            &mut sym_vis_counts,
        );
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
        // The symbol name's byte offset in the file (via `.dynstr`): a real,
        // file-backed location every consumer can render. Imports and exports
        // both anchor here. `st_value` is a virtual address, not a file offset,
        // and may point into `.bss` with no file backing — so anchoring exports
        // on the name string keeps them consistent with imports and always
        // pointing at bytes that exist in the file.
        let name_off = dynstr_offset.and_then(|base| {
            u64::try_from(sym.st_name)
                .ok()
                .map(|n| base.saturating_add(n))
        });
        if sym.st_shndx == 0 {
            // ELF doesn't bind a dynsym entry to a specific
            // DT_NEEDED library at link time — the dynamic linker
            // resolves at load. Leave `library` unset; consumers
            // that need it walk `elf.needed[]` separately.
            symbols_out.push(crate::Symbol::Import {
                name: name.to_string(),
                alias: None,
                library: None,
                offset: name_off,
                ordinal: None,
            });
        } else if sym.is_function() || sym.st_info & 0xf == 1 {
            // STB_GLOBAL = 1 (binding in upper nibble of st_info)
            symbols_out.push(crate::Symbol::Export {
                name: name.to_string(),
                offset: name_off,
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
        metrics.insert(metric!("elf.fortify_source_count"), fortify_count as f64);
    }
    if hidden_count > 0 {
        metrics.insert(metric!("elf.hidden_symbol_count"), hidden_count as f64);
    }
    if stack_canary {
        metrics.insert(metric!("elf.stack_canary"), 1.0);
    }
    if !ifuncs.is_empty() {
        values.insert_key(value_key!("elf.ifuncs"), JsonValue::Array(ifuncs));
    }
    emit_symbol_kind_histograms(&sym_type_counts, &sym_bind_counts, &sym_vis_counts, values);
}

/// Bump the type / binding / visibility tallies for one ELF symbol.
/// `STT_*` types past 15 do not exist (the field is 4 bits); same for
/// the 2-bit visibility. `STB_LOCAL` / `GLOBAL` / `WEAK` (0/1/2) are
/// the entire population in practice — anything else is processor-
/// specific and rare enough to round into the array's last slot.
fn tally_symbol_kinds(
    sym: goblin::elf::sym::Sym,
    types: &mut [u64; 16],
    bindings: &mut [u64; 4],
    visibility: &mut [u64; 4],
) {
    let stt = (sym.st_info & 0xf) as usize;
    if let Some(count) = types.get_mut(stt) {
        *count += 1;
    }
    let stb = ((sym.st_info >> 4) & 0xf) as usize;
    if let Some(count) = bindings.get_mut(stb.min(3)) {
        *count += 1;
    }
    let vis = (sym.st_other & 0x3) as usize;
    if let Some(count) = visibility.get_mut(vis) {
        *count += 1;
    }
}

/// Project the three tally arrays into `elf.symbol_kinds.*` under
/// the canonical lowercase names. Empty buckets are suppressed
/// rather than emitted as zeros to keep the JSON output focused on
/// what's actually present.
fn emit_symbol_kind_histograms(
    types: &[u64; 16],
    bindings: &[u64; 4],
    visibility: &[u64; 4],
    values: &mut Values,
) {
    const TYPE_NAMES: [&str; 16] = [
        "notype",
        "object",
        "func",
        "section",
        "file",
        "common",
        "tls",
        "stt_7",
        "stt_8",
        "stt_9",
        "gnu_ifunc",
        "stt_11",
        "stt_12",
        "stt_13",
        "stt_14",
        "stt_15",
    ];
    const BIND_NAMES: [&str; 4] = ["local", "global", "weak", "other"];
    const VIS_NAMES: [&str; 4] = ["default", "internal", "hidden", "protected"];

    let mut by_type = serde_json::Map::new();
    for (name, count) in TYPE_NAMES.iter().zip(types) {
        if *count > 0 {
            by_type.insert((*name).to_string(), JsonValue::Number((*count).into()));
        }
    }
    if !by_type.is_empty() {
        values.insert_key(
            value_key!("elf.symbol_kinds.types"),
            JsonValue::Object(by_type),
        );
    }
    let mut by_bind = serde_json::Map::new();
    for (name, count) in BIND_NAMES.iter().zip(bindings) {
        if *count > 0 {
            by_bind.insert((*name).to_string(), JsonValue::Number((*count).into()));
        }
    }
    if !by_bind.is_empty() {
        values.insert_key(
            value_key!("elf.symbol_kinds.bindings"),
            JsonValue::Object(by_bind),
        );
    }
    let mut by_vis = serde_json::Map::new();
    for (name, count) in VIS_NAMES.iter().zip(visibility) {
        if *count > 0 {
            by_vis.insert((*name).to_string(), JsonValue::Number((*count).into()));
        }
    }
    if !by_vis.is_empty() {
        values.insert_key(
            value_key!("elf.symbol_kinds.visibility"),
            JsonValue::Object(by_vis),
        );
    }
}

fn build_id(
    elf: &Elf<'_>,
    bytes: &[u8],
    segment_notes: &[Note<'_>],
    values: &mut Values,
    metrics: &mut Metrics,
    errors_out: &mut Errors,
) {
    // GNU build-id lives in a SHT_NOTE section named `.note.gnu.build-id`
    // (or `.gnu.build.attributes` in newer binutils), with a matching
    // PT_NOTE program header. Read it from the *section table* first: a
    // note-cavity infector flips that PT_NOTE program header to PT_LOAD
    // but leaves the section — and the ID — byte-identical, so a
    // segment-only walk (`iter_note_headers`) wrongly reports the ID as
    // gone and destroys the "identity retained, execution redirected"
    // evidence. Sections survive the repurposing; fall back to segments
    // only for stripped binaries that carry no section headers.
    let section_notes = drain_notes(elf.iter_note_sections(bytes, None), errors_out);
    let desc = gnu_build_id_desc(&section_notes).or_else(|| gnu_build_id_desc(segment_notes));
    if let Some(desc) = desc {
        put_str(values, value_key!("elf.build_id"), hex_encode(desc));
        metrics.insert(metric!("elf.has_build_id"), 1.0);
        metrics.insert(metric!("elf.build_id_length"), desc.len() as f64);
    }
}

/// First GNU build-id (`n_type == NT_GNU_BUILD_ID`, owner `GNU`) among
/// `notes`, or `None`.
fn gnu_build_id_desc<'a>(notes: &[Note<'a>]) -> Option<&'a [u8]> {
    notes
        .iter()
        .find(|note| note.name == "GNU" && note.n_type == 3)
        .map(|note| note.desc)
}

/// Every note a lazy goblin note walk yields, drained through `goblin_safe`.
/// Notes goblin rejects are skipped; `None` (no note segments or sections)
/// yields none.
fn drain_notes<'a>(notes: Option<NoteIterator<'a>>, errors_out: &mut Errors) -> Vec<Note<'a>> {
    let walk = notes.into_iter().flatten().flatten();
    goblin_safe::drain_or_record(walk, errors_out, crate::Stage::ElfParse)
}

/// Flag `SHT_NOTE` sections whose bytes are not covered by any note
/// program header (`PT_NOTE` or `PT_GNU_PROPERTY`). Linkers emit every
/// note with a matching program header, so an uncovered note section is
/// the note-cavity tell: an infector flipped the note's program header
/// to an executable `PT_LOAD` and left the note — its GNU build-id
/// included — intact in the section table. This is the positive
/// "identity retained, execution redirected" signal that pairs with the
/// entry / segment changes.
///
/// Two metrics: `elf.uncovered_note_count` counts every orphaned
/// note section; `elf.build_id_uncovered` fires when the
/// orphaned note is specifically the GNU build-id — the identity
/// fingerprint present on disk yet invisible to the kernel / coredump /
/// debuginfod path that reads it through the program headers. Only
/// meaningful when the file has program headers (ET_EXEC / ET_DYN);
/// relocatable objects legitimately have none.
fn note_segment_coverage(
    elf: &Elf<'_>,
    bytes: &[u8],
    metrics: &mut Metrics,
    errors_out: &mut Errors,
) {
    use goblin::elf::program_header::{PT_GNU_PROPERTY, PT_NOTE};
    use goblin::elf::section_header::SHT_NOTE;
    if elf.program_headers.is_empty() {
        return;
    }
    let note_ranges: Vec<(u64, u64)> = elf
        .program_headers
        .iter()
        .filter(|ph| ph.p_type == PT_NOTE || ph.p_type == PT_GNU_PROPERTY)
        .map(|ph| (ph.p_offset, ph.p_offset.saturating_add(ph.p_filesz)))
        .collect();
    // SHF_ALLOC = 0x2. Only *loaded* notes are expected to have a note
    // program header — the loader reads them from memory. Non-allocated
    // notes (`.note.stapsdt` SystemTap probes, `.note.gnu.gold-version`,
    // packaging notes) legitimately have no PT_NOTE, so gating on
    // SHF_ALLOC keeps a benign static binary from tripping this.
    const SHF_ALLOC: u64 = 0x2;
    let mut uncovered = 0u64;
    let mut build_id_orphaned = false;
    for sh in &elf.section_headers {
        if sh.sh_type != SHT_NOTE || sh.sh_size == 0 || sh.sh_flags & SHF_ALLOC == 0 {
            continue;
        }
        let start = sh.sh_offset;
        let end = sh.sh_offset.saturating_add(sh.sh_size);
        if note_ranges.iter().any(|(s, e)| start >= *s && end <= *e) {
            continue;
        }
        uncovered += 1;
        // Is the orphaned note the GNU build-id? Read it back through its
        // own section name so the check is independent of ordering.
        let name = elf.shdr_strtab.get_at(sh.sh_name);
        let notes = drain_notes(elf.iter_note_sections(bytes, name), errors_out);
        if gnu_build_id_desc(&notes).is_some() {
            build_id_orphaned = true;
        }
    }
    if uncovered > 0 {
        metrics.insert(metric!("elf.uncovered_note_count"), uncovered as f64);
    }
    if build_id_orphaned {
        metrics.insert(metric!("elf.build_id_uncovered"), 1.0);
    }
}

/// File-layout anomalies over the section table, keyed by file offset:
/// sections whose bytes run past EOF, `SHF_ALLOC` sections mapped by no
/// `PT_LOAD`, and mutually overlapping section ranges. Toolchains lay
/// sections out as disjoint, in-bounds slices, each allocatable one
/// inside a load segment; carving, appending, and packing break those
/// invariants. NOBITS sections (`.bss`, `.tbss`) own no file bytes and
/// are skipped.
fn section_file_anomalies(elf: &Elf<'_>, bytes: &[u8], metrics: &mut Metrics) {
    use goblin::elf::program_header::PT_LOAD;
    const SHT_NOBITS: u32 = 8;
    const SHF_ALLOC: u64 = 0x2;
    let file_len = bytes.len() as u64;

    let load_ranges: Vec<(u64, u64)> = elf
        .program_headers
        .iter()
        .filter(|ph| ph.p_type == PT_LOAD)
        .map(|ph| (ph.p_offset, ph.p_offset.saturating_add(ph.p_filesz)))
        .collect();

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
            && !load_ranges.iter().any(|(s, e)| start >= *s && end <= *e)
        {
            uncovered_alloc += 1;
        }
        ranges.push((start, end, idx));
    }

    // Overlap: sort by start; a section whose end runs past the next
    // section's start intersects it. Count distinct sections involved,
    // mirroring `elf.segment_overlap_count`.
    ranges.sort_unstable();
    let mut overlap: std::collections::HashSet<usize> = std::collections::HashSet::new();
    for w in ranges.windows(2) {
        let &[(_, a_end, a_idx), (b_start, _, b_idx)] = w else {
            continue;
        };
        if a_end > b_start {
            overlap.insert(a_idx);
            overlap.insert(b_idx);
        }
    }

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

fn interpreter(elf: &Elf<'_>, values: &mut Values) {
    if let Some(interp) = elf.interpreter {
        put_str(values, value_key!("elf.interpreter"), interp);
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
