//! Mach-O extractor.
//!
//! Reads macOS / iOS executables, dylibs, kernel extensions, and Mach-O
//! FAT (universal) binaries. Surfaces header fields, the load-command
//! list, LC_LOAD_DYLIB references, LC_RPATH entries, the LC_UUID, and
//! code-signature presence.
//!
//! For FAT binaries, exposes per-arch slices under `macho.slices[]`
//! and surfaces the first slice's metadata at the top level so simple
//! consumers don't have to enumerate the array.

use goblin::mach::{self, Mach, MachO};
use serde_json::{json, Value as JsonValue};

use crate::error::Error;
use crate::formats::common::{extract_ascii_strings, put_str, put_u64};
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

    let parsed = Mach::parse(bytes).map_err(|e| Error::malformed("macho", e.to_string()))?;
    match parsed {
        Mach::Binary(macho) => {
            single_arch(&macho, bytes, values, metrics, sections_out);
        }
        Mach::Fat(fat) => fat_binary(bytes, &fat, values, metrics, sections_out),
    }
    Ok(())
}

fn fat_binary(
    bytes: &[u8],
    fat: &mach::MultiArch<'_>,
    values: &mut Values,
    metrics: &mut Metrics,
    sections_out: &mut Vec<Section>,
) {
    let mut archs: Vec<JsonValue> = Vec::new();
    for (idx, slice) in fat.iter_arches().enumerate() {
        let Ok(arch) = slice else { continue };
        let slice_bytes = &bytes[arch.offset as usize
            ..(arch.offset as usize).saturating_add(arch.size as usize).min(bytes.len())];
        let Ok(macho) = MachO::parse(slice_bytes, 0) else {
            continue;
        };
        archs.push(json!({
            "cpu_type": cpu_type_string(macho.header.cputype()),
            "cpu_subtype": macho.header.cpusubtype(),
            "file_type": file_type_string(macho.header.filetype),
            "libraries": macho.libs.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
        }));
        if idx == 0 {
            single_arch(&macho, slice_bytes, values, metrics, sections_out);
        }
    }
    metrics.insert("macho.slice_count", archs.len() as f64);
    values.insert("macho.slices", JsonValue::Array(archs));
}

fn single_arch(
    macho: &MachO<'_>,
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    sections_out: &mut Vec<Section>,
) {
    extract_sections(macho, bytes, metrics, sections_out);
    extract_header_and_loads(macho, bytes, values, metrics);
    super::build_toolchain::from_macho(values, sections_out);
}

/// Walk `LC_SEGMENT` / `LC_SEGMENT_64` and surface each named
/// section. Mach-O nests sections inside segments; we flatten the
/// hierarchy with the canonical `__SEGMENT,__section` naming so
/// `__TEXT,__text` etc. survives to the output.
fn extract_sections(
    macho: &MachO<'_>,
    bytes: &[u8],
    metrics: &mut Metrics,
    sections_out: &mut Vec<Section>,
) {
    let mut section_idx = 0_usize;
    for segment in &macho.segments {
        let segment_name = segment.name().unwrap_or("").to_owned();
        let flags = macho_segment_flags(segment.initprot);
        let Ok(secs) = segment.sections() else {
            continue;
        };
        for (section, _data) in secs {
            let section_name = section.name().unwrap_or("").to_owned();
            let display = if section_name.is_empty() {
                segment_name.clone()
            } else {
                format!("{segment_name},{section_name}")
            };
            let file_offset = u64::from(section.offset);
            let file_size = section.size;
            if file_size > 0 {
                let e = section_entropy(bytes, file_offset, file_size);
                metrics.insert(format!("sections[{section_idx}].entropy"), e);
            }
            sections_out.push(Section {
                name: display,
                vaddr: section.addr,
                vsize: section.size,
                file_offset,
                file_size,
                flags: flags.iter().map(|s| (*s).to_string()).collect(),
            });
            section_idx += 1;
        }
    }
}

fn macho_segment_flags(initprot: u32) -> Vec<&'static str> {
    // VM_PROT_READ = 1, VM_PROT_WRITE = 2, VM_PROT_EXECUTE = 4.
    let mut out = Vec::new();
    if initprot & 1 != 0 {
        out.push("readable");
    }
    if initprot & 2 != 0 {
        out.push("writable");
    }
    if initprot & 4 != 0 {
        out.push("executable");
    }
    out
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

fn extract_header_and_loads(macho: &MachO<'_>, bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    put_str(values, "macho.cpu_type", cpu_type_string(macho.header.cputype()));
    put_u64(values, "macho.cpu_subtype", u64::from(macho.header.cpusubtype()));
    put_str(values, "macho.file_type", file_type_string(macho.header.filetype));
    put_u64(values, "macho.flags_raw", u64::from(macho.header.flags));
    put_str(values, "macho.endian", if macho.little_endian { "little" } else { "big" });

    let libs: Vec<JsonValue> = macho
        .libs
        .iter()
        .filter(|s| !s.is_empty() && **s != "self")
        .map(|s| JsonValue::String((*s).to_string()))
        .collect();
    metrics.insert("macho.library_count", libs.len() as f64);
    values.insert("macho.libraries", JsonValue::Array(libs));

    let rpaths: Vec<JsonValue> = macho
        .rpaths
        .iter()
        .map(|s| JsonValue::String((*s).to_string()))
        .collect();
    if !rpaths.is_empty() {
        values.insert("macho.rpaths", JsonValue::Array(rpaths));
    }

    // Load commands are the most useful structural fingerprint of a
    // Mach-O. Emit their `cmd` (LC_*) names in order.
    let lcs: Vec<JsonValue> = macho
        .load_commands
        .iter()
        .map(|lc| JsonValue::String(load_command_name(lc.command.cmd()).to_string()))
        .collect();
    metrics.insert("macho.load_command_count", lcs.len() as f64);
    values.insert("macho.load_commands", JsonValue::Array(lcs));

    // Find the LC_CODE_SIGNATURE entry — its `dataoff`/`datasize`
    // point at the embedded code-signature blob inside the
    // `__LINKEDIT` segment. Presence/absence of any
    // `macho.code_signature.*` field IS the "is this binary signed"
    // signal; we don't emit a separate boolean for it.
    let code_sig = macho.load_commands.iter().find_map(|lc| match lc.command {
        mach::load_command::CommandVariant::CodeSignature(cs) => Some(cs),
        _ => None,
    });
    if let Some(cs) = code_sig {
        super::macho_code_signature::parse(
            bytes,
            cs.dataoff as usize,
            cs.datasize as usize,
            values,
        );
    }

    // LC_UUID — 128-bit build fingerprint. Stable per-build, used by
    // dSYM correlation and crash-report symbolication. The canonical
    // text form is the lowercase 8-4-4-4-12 hyphenated layout that
    // `dwarfdump --uuid` emits.
    if let Some(uuid) = macho.load_commands.iter().find_map(|lc| match lc.command {
        mach::load_command::CommandVariant::Uuid(c) => Some(c.uuid),
        _ => None,
    }) {
        put_str(values, "macho.uuid", format_macho_uuid(&uuid));
    }

    // __TEXT,__info_plist — many Apple tools embed a CFBundle-style
    // Info.plist directly in the binary instead of pairing it with a
    // .app bundle. The content is XML or binary plist; we parse and
    // surface the dictionary under `macho.info_plist`. Forensically
    // valuable: the plist carries `CFBundleIdentifier`, executable
    // name, and any `LSEnvironment` / `LSUIElement` flags that affect
    // load behaviour.
    info_plist_section(macho, bytes, values);
    build_version(macho, bytes, values);
    source_version(macho, values);
    install_name(macho, values);
    load_dylibs(macho, values);
    linker_options(macho, bytes, values);
    objc_image_info(macho, bytes, values);

    binary_flags(macho, metrics);
}

/// `LC_LINKER_OPTION` (cmd `0x2d`) — embeds linker arguments
/// (`-framework Foundation`, `-lc++`, …) the link step would
/// otherwise consume off the command line. The body is a `u32`
/// count followed by `count` NUL-terminated strings, padded to
/// 8-byte alignment. Surfaces each string as an element of
/// `macho.linker_options[]`.
fn linker_options(macho: &MachO<'_>, bytes: &[u8], values: &mut Values) {
    let little_endian = macho.little_endian;
    let mut all: Vec<JsonValue> = Vec::new();
    for lc in &macho.load_commands {
        let mach::load_command::CommandVariant::LinkerOption(c) = lc.command else {
            continue;
        };
        let cmd_offset = lc.offset;
        let cmd_size = c.cmdsize as usize;
        let header_size = 12_usize; // cmd + cmdsize + count
        let body_start = cmd_offset.saturating_add(header_size);
        let body_end = cmd_offset.saturating_add(cmd_size).min(bytes.len());
        if body_start + 4 > body_end {
            continue;
        }
        let count_field_start = cmd_offset.saturating_add(8);
        let count = read_u32(
            &bytes[count_field_start..count_field_start + 4],
            0,
            little_endian,
        ) as usize;
        let body = &bytes[body_start..body_end];
        let mut taken = 0;
        for chunk in body.split(|&b| b == 0) {
            if taken >= count {
                break;
            }
            if chunk.is_empty() {
                continue;
            }
            if let Ok(s) = std::str::from_utf8(chunk) {
                all.push(JsonValue::String(s.to_string()));
                taken += 1;
            }
        }
    }
    if !all.is_empty() {
        values.insert("macho.linker_options", JsonValue::Array(all));
    }
}

/// `__OBJC,__image_info` / `__DATA,__objc_imageinfo` — 8-byte
/// section: `(version: u32, flags: u32)`. The Swift ABI version
/// lives in `flags[15:8]`; presence alone signals the binary
/// links the Objective-C runtime.
fn objc_image_info(macho: &MachO<'_>, bytes: &[u8], values: &mut Values) {
    for segment in &macho.segments {
        let Ok(sections) = segment.sections() else {
            continue;
        };
        for (section, _data) in sections {
            let name = section.name().unwrap_or("");
            if name != "__image_info" && name != "__objc_imageinfo" {
                continue;
            }
            let off = section.offset as usize;
            let end = off.saturating_add(section.size as usize).min(bytes.len());
            if end < off + 8 {
                return;
            }
            let little_endian = macho.little_endian;
            let _version = read_u32(&bytes[off..off + 4], 0, little_endian);
            let flags = read_u32(&bytes[off + 4..off + 8], 0, little_endian);
            let swift_version = (flags >> 8) & 0xff;
            let mut obj = serde_json::Map::new();
            obj.insert("flags_raw".into(), JsonValue::Number(u64::from(flags).into()));
            if swift_version != 0 {
                obj.insert(
                    "swift_version".into(),
                    JsonValue::Number(u64::from(swift_version).into()),
                );
            }
            values.insert("macho.objc", JsonValue::Object(obj));
            return;
        }
    }
}

/// Per-dylib metadata for every `LC_LOAD_DYLIB` / `LC_LOAD_WEAK_DYLIB` /
/// `LC_REEXPORT_DYLIB` / `LC_LAZY_LOAD_DYLIB` command. Surfaces the
/// path (already in `macho.libraries[]`), the load kind (`load` /
/// `load_weak` / `reexport` / `lazy_load`), the dylib's declared
/// `current_version` and `compatibility_version`, and the linker
/// timestamp it was prebound against. `LC_ID_DYLIB` is excluded —
/// that's the dylib's own identity, already exposed as
/// `macho.install_name`.
fn load_dylibs(macho: &MachO<'_>, values: &mut Values) {
    let mut entries: Vec<JsonValue> = Vec::new();
    for lc in &macho.load_commands {
        let (kind, dylib) = match lc.command {
            mach::load_command::CommandVariant::LoadDylib(c) => ("load", c.dylib),
            mach::load_command::CommandVariant::LoadWeakDylib(c) => ("load_weak", c.dylib),
            mach::load_command::CommandVariant::ReexportDylib(c) => ("reexport", c.dylib),
            mach::load_command::CommandVariant::LazyLoadDylib(c) => ("lazy_load", c.dylib),
            _ => continue,
        };
        // The dylib name is an `LcStr` (offset into the command's
        // bytes). Goblin's `MachO::libs` array carries the resolved
        // strings in load-command order with the ID_DYLIB / "self"
        // slot at index 0; the LoadDylib variants we keep here start
        // at index 1.
        let idx = entries.len() + 1;
        let path = macho.libs.get(idx).copied().unwrap_or("");
        let mut entry = serde_json::Map::new();
        entry.insert("path".into(), JsonValue::String(path.to_string()));
        entry.insert("kind".into(), JsonValue::String(kind.to_string()));
        entry.insert(
            "current_version".into(),
            JsonValue::String(decode_version_nibbles(dylib.current_version)),
        );
        entry.insert(
            "compatibility_version".into(),
            JsonValue::String(decode_version_nibbles(dylib.compatibility_version)),
        );
        if dylib.timestamp != 0 {
            entry.insert("timestamp".into(), JsonValue::Number(dylib.timestamp.into()));
        }
        entries.push(JsonValue::Object(entry));
    }
    if !entries.is_empty() {
        values.insert("macho.load_dylibs", JsonValue::Array(entries));
    }
}

/// `LC_BUILD_VERSION` — declares the platform (`macos`, `ios`, `tvos`,
/// `watchos`, …), the minimum-supported OS version, the SDK version
/// the toolchain was built against, and a list of `BuildToolVersion`
/// entries naming each tool (clang, ld, swift, …) that contributed.
/// Replaces the legacy `LC_VERSION_MIN_*` commands on modern (10.14+)
/// toolchains.
///
/// `goblin` parses the 24-byte header but stops there; we read the
/// `ntools` × 8-byte `BuildToolVersion` array that follows.
fn build_version(macho: &MachO<'_>, bytes: &[u8], values: &mut Values) {
    let Some((lc_offset, bv)) = macho.load_commands.iter().find_map(|lc| match lc.command {
        mach::load_command::CommandVariant::BuildVersion(c) => Some((lc.offset, c)),
        _ => None,
    }) else {
        return;
    };
    let mut obj = serde_json::Map::new();
    obj.insert(
        "platform".into(),
        JsonValue::String(platform_name(bv.platform).to_string()),
    );
    if bv.minos != 0 {
        obj.insert("min_os".into(), JsonValue::String(decode_version_nibbles(bv.minos)));
    }
    if bv.sdk != 0 {
        obj.insert("sdk".into(), JsonValue::String(decode_version_nibbles(bv.sdk)));
    }
    if bv.ntools > 0 {
        let header_size = 24_usize;
        let tools_start = lc_offset.saturating_add(header_size);
        let entries_bytes = (bv.ntools as usize).saturating_mul(8);
        let tools_end = tools_start.saturating_add(entries_bytes).min(bytes.len());
        if tools_start + 8 <= tools_end {
            let little_endian = macho.little_endian;
            let tools: Vec<JsonValue> = bytes[tools_start..tools_end]
                .chunks_exact(8)
                .map(|c| {
                    let tool = read_u32(c, 0, little_endian);
                    let version = read_u32(c, 4, little_endian);
                    let mut entry = serde_json::Map::new();
                    entry.insert(
                        "tool".into(),
                        JsonValue::String(build_tool_name(tool).to_string()),
                    );
                    entry.insert(
                        "version".into(),
                        JsonValue::String(decode_version_nibbles(version)),
                    );
                    JsonValue::Object(entry)
                })
                .collect();
            if !tools.is_empty() {
                obj.insert("tools".into(), JsonValue::Array(tools));
            }
        }
    }
    values.insert("macho.build_version", JsonValue::Object(obj));
}

fn read_u32(bytes: &[u8], offset: usize, little_endian: bool) -> u32 {
    let arr: [u8; 4] = bytes[offset..offset + 4]
        .try_into()
        .unwrap_or([0, 0, 0, 0]);
    if little_endian {
        u32::from_le_bytes(arr)
    } else {
        u32::from_be_bytes(arr)
    }
}

/// `<mach-o/loader.h>` `TOOL_*` constants.
fn build_tool_name(tool: u32) -> &'static str {
    match tool {
        1 => "clang",
        2 => "swift",
        3 => "ld",
        4 => "lld",
        5 => "metal",
        _ => "unknown",
    }
}

/// `LC_SOURCE_VERSION` — developer-stamped source-tree version
/// (`a.b.c.d.e` packed as 24/10/10/10/10 bits). Almost always
/// unset (zero) on stock binaries; populated when the build system
/// explicitly threads a version through the linker.
fn source_version(macho: &MachO<'_>, values: &mut Values) {
    let Some(sv) = macho.load_commands.iter().find_map(|lc| match lc.command {
        mach::load_command::CommandVariant::SourceVersion(c) => Some(c.version),
        _ => None,
    }) else {
        return;
    };
    if sv == 0 {
        return;
    }
    let a = (sv >> 40) & 0xFF_FFFF;
    let b = (sv >> 30) & 0x3FF;
    let c = (sv >> 20) & 0x3FF;
    let d = (sv >> 10) & 0x3FF;
    let e = sv & 0x3FF;
    put_str(values, "macho.source_version", format!("{a}.{b}.{c}.{d}.{e}"));
}

/// `LC_ID_DYLIB` — the dylib's own install name (only present on
/// shared libraries / frameworks). Always the first dylib command;
/// downstream `LC_LOAD_DYLIB`s reference other libraries.
fn install_name(macho: &MachO<'_>, values: &mut Values) {
    let Some(id) = macho.load_commands.iter().find_map(|lc| match lc.command {
        mach::load_command::CommandVariant::IdDylib(c) => Some(c),
        _ => None,
    }) else {
        return;
    };
    // The Dylib `name` is an offset into the command bytes; goblin
    // surfaces every dylib path through `macho.libs`, with the
    // ID_DYLIB slot at index 0 (or "self" for non-dylibs). For the
    // install-name field we want the resolved string — pull it from
    // `libs[0]` when the binary is a dylib and the slot isn't `self`.
    let _ = id; // suppress unused; resolution done via libs below
    if let Some(name) = macho.libs.first().copied() {
        if !name.is_empty() && name != "self" {
            put_str(values, "macho.install_name", name);
        }
    }
}

/// Decode a Mach-O version field (`X.Y.Z` packed as `xxxx.yy.zz`
/// nibbles in a `u32`).
fn decode_version_nibbles(v: u32) -> String {
    let x = (v >> 16) & 0xFFFF;
    let y = (v >> 8) & 0xFF;
    let z = v & 0xFF;
    format!("{x}.{y}.{z}")
}

/// Map `LC_BUILD_VERSION.platform` to a canonical lowercase name.
fn platform_name(p: u32) -> &'static str {
    // `<mach-o/loader.h>` `PLATFORM_*`.
    match p {
        1 => "macos",
        2 => "ios",
        3 => "tvos",
        4 => "watchos",
        5 => "bridgeos",
        6 => "maccatalyst",
        7 => "ios_simulator",
        8 => "tvos_simulator",
        9 => "watchos_simulator",
        10 => "driverkit",
        11 => "visionos",
        12 => "visionos_simulator",
        _ => "unknown",
    }
}

/// Cross-format `binary.*` metrics derivable from Mach-O header / load
/// commands.
fn binary_flags(macho: &MachO<'_>, metrics: &mut Metrics) {
    // PIE: `MH_PIE = 0x00200000` in the header flags. Set by the
    // linker for position-independent executables; required for
    // App Store / hardened runtime.
    const MH_PIE: u32 = 0x0020_0000;
    let is_pie = macho.header.flags & MH_PIE != 0;
    metrics.insert("binary.is_pie", f64::from(u8::from(is_pie)));

    // Stripped: `LC_SYMTAB.nsyms == 0`. The `nlist` table is the
    // Mach-O equivalent of ELF's `.symtab`; `strip` zeroes it out.
    let nsyms = macho.load_commands.iter().find_map(|lc| match lc.command {
        mach::load_command::CommandVariant::Symtab(st) => Some(st.nsyms),
        _ => None,
    });
    let is_stripped = nsyms.is_some_and(|n| n == 0);
    metrics.insert("binary.is_stripped", f64::from(u8::from(is_stripped)));
}

fn info_plist_section(macho: &MachO<'_>, bytes: &[u8], values: &mut Values) {
    for segment in &macho.segments {
        let Ok(sections) = segment.sections() else {
            continue;
        };
        for (section, _data) in sections {
            if section.name().unwrap_or("") != "__info_plist" {
                continue;
            }
            let off = section.offset as usize;
            let len = section.size as usize;
            let end = off.saturating_add(len);
            if off >= bytes.len() || end > bytes.len() || len == 0 {
                return;
            }
            let plist_bytes = &bytes[off..end];
            if let Ok(parsed) = plist::Value::from_reader(std::io::Cursor::new(plist_bytes)) {
                values.insert("macho.info_plist", plist_to_json(parsed));
            }
            return;
        }
    }
}

fn plist_to_json(value: plist::Value) -> JsonValue {
    use plist::Value as P;
    match value {
        P::String(s) => JsonValue::String(s),
        P::Integer(i) => i
            .as_signed()
            .map(|n| JsonValue::Number(n.into()))
            .or_else(|| i.as_unsigned().map(|u| JsonValue::Number(u.into())))
            .unwrap_or(JsonValue::Null),
        P::Real(f) => {
            serde_json::Number::from_f64(f).map_or(JsonValue::Null, JsonValue::Number)
        }
        P::Boolean(b) => JsonValue::Bool(b),
        P::Date(d) => JsonValue::String(format!("{d:?}")),
        P::Array(arr) => JsonValue::Array(arr.into_iter().map(plist_to_json).collect()),
        P::Dictionary(dict) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in dict {
                obj.insert(k, plist_to_json(v));
            }
            JsonValue::Object(obj)
        }
        _ => JsonValue::Null,
    }
}

fn format_macho_uuid(b: &[u8; 16]) -> String {
    // RFC-4122-style hyphenation, kept lowercase to match every Apple
    // tool's output (codesign, dwarfdump, otool -l).
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3],
        b[4], b[5], b[6], b[7], b[8], b[9],
        b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

fn cpu_type_string(cpu_type: u32) -> &'static str {
    // From `<mach/machine.h>` `CPU_TYPE_*`.
    match cpu_type {
        0x0000_0007 => "x86",
        0x0100_0007 => "x86_64",
        0x0000_000c => "arm",
        0x0100_000c => "arm64",
        0x0200_000c => "arm64_32",
        0x0000_0012 => "powerpc",
        0x0100_0012 => "powerpc64",
        _ => "unknown",
    }
}

fn file_type_string(filetype: u32) -> &'static str {
    // From `<mach-o/loader.h>` `MH_*`.
    match filetype {
        0x1 => "object",
        0x2 => "executable",
        0x3 => "fvmlib",
        0x4 => "core",
        0x5 => "preload",
        0x6 => "dylib",
        0x7 => "dylinker",
        0x8 => "bundle",
        0x9 => "dylib_stub",
        0xa => "dsym",
        0xb => "kext_bundle",
        0xc => "fileset",
        _ => "unknown",
    }
}

fn load_command_name(cmd: u32) -> &'static str {
    // Subset of `LC_*`. Comprehensive enough for forensic fingerprinting.
    match cmd {
        0x01 => "LC_SEGMENT",
        0x02 => "LC_SYMTAB",
        0x0b => "LC_DYSYMTAB",
        0x0c => "LC_LOAD_DYLIB",
        0x0d => "LC_ID_DYLIB",
        0x0e => "LC_LOAD_DYLINKER",
        0x0f => "LC_ID_DYLINKER",
        0x10 => "LC_PREBOUND_DYLIB",
        0x11 => "LC_ROUTINES",
        0x12 => "LC_SUB_FRAMEWORK",
        0x18 => "LC_LOAD_WEAK_DYLIB",
        0x19 => "LC_SEGMENT_64",
        0x1a => "LC_ROUTINES_64",
        0x1b => "LC_UUID",
        0x1c => "LC_RPATH",
        0x1d => "LC_CODE_SIGNATURE",
        0x1e => "LC_SEGMENT_SPLIT_INFO",
        0x1f => "LC_REEXPORT_DYLIB",
        0x20 => "LC_LAZY_LOAD_DYLIB",
        0x21 => "LC_ENCRYPTION_INFO",
        0x22 => "LC_DYLD_INFO",
        0x24 => "LC_VERSION_MIN_MACOSX",
        0x25 => "LC_VERSION_MIN_IPHONEOS",
        0x26 => "LC_FUNCTION_STARTS",
        0x27 => "LC_DYLD_ENVIRONMENT",
        0x28 => "LC_MAIN",
        0x29 => "LC_DATA_IN_CODE",
        0x2a => "LC_SOURCE_VERSION",
        0x2b => "LC_DYLIB_CODE_SIGN_DRS",
        0x2c => "LC_ENCRYPTION_INFO_64",
        0x2d => "LC_LINKER_OPTION",
        0x2e => "LC_LINKER_OPTIMIZATION_HINT",
        0x2f => "LC_VERSION_MIN_TVOS",
        0x30 => "LC_VERSION_MIN_WATCHOS",
        0x31 => "LC_NOTE",
        0x32 => "LC_BUILD_VERSION",
        0x33 => "LC_DYLD_EXPORTS_TRIE",
        0x34 => "LC_DYLD_CHAINED_FIXUPS",
        0x35 => "LC_FILESET_ENTRY",
        // High bit set indicates required for execution; mask it off.
        other if other & 0x8000_0000 != 0 => load_command_name(other & 0x7fff_ffff),
        _ => "LC_UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_type_string_known() {
        assert_eq!(cpu_type_string(0x0100_0007), "x86_64");
        assert_eq!(cpu_type_string(0x0100_000c), "arm64");
        assert_eq!(cpu_type_string(0xffff_ffff), "unknown");
    }

    #[test]
    fn file_type_string_known() {
        assert_eq!(file_type_string(0x2), "executable");
        assert_eq!(file_type_string(0x6), "dylib");
        assert_eq!(file_type_string(0xb), "kext_bundle");
    }

    #[test]
    fn load_command_name_strips_required_bit() {
        // LC_LOAD_DYLIB with `LC_REQ_DYLD` bit set
        assert_eq!(load_command_name(0x8000_000c), "LC_LOAD_DYLIB");
    }
}
