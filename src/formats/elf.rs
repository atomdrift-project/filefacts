//! ELF extractor.
//!
//! Reads Linux executables, shared libraries, and core dumps. Surfaces
//! the file header, dynamic-section facts (DT_NEEDED, RPATH, SONAME),
//! section table, dynamic symbol table imports/exports, and the
//! GNU build-id when present.

use goblin::elf::{dynamic, header, program_header, Elf};
use serde_json::Value as JsonValue;

use crate::error::Error;
use crate::formats::common::{extract_ascii_strings, hex_encode, put_str, put_u64};
use crate::output::{Metrics, Section, Strings, Values};
use crate::scan::entropy;

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    strings: &mut Strings,
    metrics: &mut Metrics,
    sections_out: &mut Vec<Section>,
) -> Result<(), Error> {
    extract_ascii_strings(bytes, strings);

    let elf = Elf::parse(bytes).map_err(|e| Error::malformed("elf", e.to_string()))?;

    elf_header(&elf, values);
    dynamic(&elf, values);
    sections(&elf, bytes, metrics, sections_out);
    symbols(&elf, values, metrics);
    build_id(&elf, bytes, values);
    interpreter(&elf, values);
    relro(&elf, values);
    needed_versions(&elf, values);
    provided_versions(&elf, values);
    stripped_metadata(&elf, values, metrics);
    comment(&elf, bytes, values);
    dt_flags(&elf, values);
    abi_tag(&elf, bytes, values);
    gnu_property(&elf, bytes, values);
    binary_flags(&elf, metrics);
    linker_family(values);
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
fn comment(elf: &Elf<'_>, bytes: &[u8], values: &mut Values) {
    let Some(data) = read_section(elf, bytes, ".comment") else {
        return;
    };
    let entries: Vec<JsonValue> = data
        .split(|&b| b == 0)
        .filter(|chunk| !chunk.is_empty())
        .filter_map(|chunk| std::str::from_utf8(chunk).ok())
        .filter(|s| !s.trim().is_empty())
        .map(|s| JsonValue::String(s.to_string()))
        .collect();
    if !entries.is_empty() {
        values.insert("elf.comment", JsonValue::Array(entries));
    }
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
    if !flags.is_empty() || !flags1.is_empty() {
        let mut obj = serde_json::Map::new();
        if !flags.is_empty() {
            obj.insert(
                "flags".into(),
                JsonValue::Array(flags.iter().map(|s| JsonValue::String((*s).to_string())).collect()),
            );
        }
        if !flags1.is_empty() {
            obj.insert(
                "flags_1".into(),
                JsonValue::Array(flags1.iter().map(|s| JsonValue::String((*s).to_string())).collect()),
            );
        }
        values.insert("elf.dt_flags", JsonValue::Object(obj));
    }
}

fn decompose_df(v: u64, out: &mut Vec<&'static str>) {
    if v & 0x1 != 0 { out.push("origin"); }
    if v & 0x2 != 0 { out.push("symbolic"); }
    if v & 0x4 != 0 { out.push("textrel"); }
    if v & 0x8 != 0 { out.push("bind_now"); }
    if v & 0x10 != 0 { out.push("static_tls"); }
}

fn decompose_df1(v: u64, out: &mut Vec<&'static str>) {
    if v & 0x0000_0001 != 0 { out.push("now"); }
    if v & 0x0000_0002 != 0 { out.push("global"); }
    if v & 0x0000_0008 != 0 { out.push("nodelete"); }
    if v & 0x0000_0010 != 0 { out.push("loadfltr"); }
    if v & 0x0000_0040 != 0 { out.push("initfirst"); }
    if v & 0x0000_0080 != 0 { out.push("noopen"); }
    if v & 0x0000_0100 != 0 { out.push("origin"); }
    if v & 0x0000_0800 != 0 { out.push("nodump"); }
    if v & 0x0000_2000 != 0 { out.push("noopen2"); }
    if v & 0x0800_0000 != 0 { out.push("pie"); }
    if v & 0x1000_0000 != 0 { out.push("kmod"); }
    if v & 0x4000_0000 != 0 { out.push("noreloc"); }
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
fn gnu_property(elf: &Elf<'_>, bytes: &[u8], values: &mut Values) {
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
                u32::from_le_bytes(note.desc[off + 4..off + 8].try_into().unwrap_or([0; 4])) as usize;
            let data_start = off + 8;
            let data_end = data_start.saturating_add(pr_datasz);
            if data_end > note.desc.len() {
                break;
            }
            if let Some(name) = gnu_property_name(pr_type, is_aarch64) {
                let mut entry = serde_json::Map::new();
                entry.insert("type".into(), JsonValue::String(name.to_string()));
                if pr_datasz == 4 {
                    let v =
                        u32::from_le_bytes(note.desc[data_start..data_end].try_into().unwrap_or([0; 4]));
                    entry.insert("value".into(), JsonValue::String(format!("0x{v:x}")));
                    if is_aarch64 && pr_type == 0xC000_0000 {
                        // AARCH64_FEATURE_1_AND — bit-decomposed
                        // features that link-time enforcement
                        // requires (BTI / PAC / GCS).
                        let mut feats = Vec::new();
                        if v & 0x1 != 0 { feats.push("bti"); }
                        if v & 0x2 != 0 { feats.push("pac"); }
                        if v & 0x4 != 0 { feats.push("gcs"); }
                        if !feats.is_empty() {
                            entry.insert(
                                "features".into(),
                                JsonValue::Array(
                                    feats.into_iter().map(|s| JsonValue::String(s.into())).collect(),
                                ),
                            );
                        }
                    }
                } else if is_aarch64 && pr_type == 0xC000_0001 && pr_datasz == 16 {
                    // AARCH64_FEATURE_PAUTH — 16 bytes, two u64
                    // words identifying the key-generation scheme.
                    let platform = u64::from_le_bytes(
                        note.desc[data_start..data_start + 8].try_into().unwrap_or([0; 8]),
                    );
                    let version = u64::from_le_bytes(
                        note.desc[data_start + 8..data_start + 16]
                            .try_into()
                            .unwrap_or([0; 8]),
                    );
                    let scheme = format!("{}:{}", pauth_platform_name(platform), version);
                    entry.insert("platform".into(), JsonValue::String(pauth_platform_name(platform).into()));
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
    let debug_or_comment_gone =
        !present.contains(".comment") || !present.contains(".debug_info");
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
    put_str(values, "elf.class", if elf.is_64 { "elf64" } else { "elf32" });
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

fn sections(
    elf: &Elf<'_>,
    bytes: &[u8],
    metrics: &mut Metrics,
    sections_out: &mut Vec<Section>,
) {
    for (idx, sh) in elf.section_headers.iter().enumerate() {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_owned();
        // SHT_NOBITS (8) sections have no file bytes. Other types
        // occupy `sh_offset..sh_offset + sh_size` in the file.
        let (file_offset, file_size) = if sh.sh_type == 8 {
            (sh.sh_offset, 0)
        } else {
            (sh.sh_offset, sh.sh_size)
        };
        if file_size > 0 {
            let e = section_entropy(bytes, file_offset, file_size);
            metrics.insert(format!("sections[{idx}].entropy"), e);
        }
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

fn symbols(elf: &Elf<'_>, values: &mut Values, metrics: &mut Metrics) {
    // Dynamic-symbol table: imports are undefined (`SHN_UNDEF`, section
    // index 0); exports are defined globals/weaks. STT_GNU_IFUNC
    // entries are split into a dedicated `elf.ifuncs[]` — they're rare
    // (libc memcpy/strcmp resolvers, glibc startup) and trait authors
    // want to detect their presence directly without scanning all
    // imports.
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    let mut ifuncs = Vec::new();
    for sym in &elf.dynsyms {
        let Some(name) = elf.dynstrtab.get_at(sym.st_name) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let stt = sym.st_info & 0xf;
        if stt == goblin::elf::sym::STT_GNU_IFUNC {
            ifuncs.push(JsonValue::String(name.to_string()));
        }
        if sym.st_shndx == 0 {
            imports.push(JsonValue::String(name.to_string()));
        } else if sym.is_function() || sym.st_info & 0xf == 1 {
            // STB_GLOBAL = 1 (binding in upper nibble of st_info)
            exports.push(JsonValue::String(name.to_string()));
        }
    }
    metrics.insert("elf.import_count", imports.len() as f64);
    metrics.insert("elf.export_count", exports.len() as f64);
    values.insert("elf.imports", JsonValue::Array(imports));
    values.insert("elf.exports", JsonValue::Array(exports));
    if !ifuncs.is_empty() {
        values.insert("elf.ifuncs", JsonValue::Array(ifuncs));
    }
}

fn build_id(elf: &Elf<'_>, bytes: &[u8], values: &mut Values) {
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
        out.push("execinstr");
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

    #[test]
    fn machine_string_handles_known() {
        assert_eq!(machine_string(header::EM_X86_64), "x86_64");
        assert_eq!(machine_string(header::EM_AARCH64), "aarch64");
        assert_eq!(machine_string(0xeeee), "unknown");
    }
}
