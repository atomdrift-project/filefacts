//! PE / COFF (Portable Executable) extractor.
//!
//! Reads Windows executables, DLLs, sys drivers, and CRX-wrapped PEs.
//! Surfaces COFF header fields, the optional-header subsystem and
//! characteristics, the section table, imports and exports, and the
//! version-info resource when present.
//!
//! The schema follows the names PE-the-format gives its own fields,
//! lightly snake-cased. `IMAGE_FILE_HEADER.Machine` becomes
//! `pe.coff.machine`; `IMAGE_OPTIONAL_HEADER.Subsystem` becomes
//! `pe.optional.subsystem`; the IAT is exposed as `pe.imports[]`.

use goblin::pe::{header::CoffHeader, optional_header::OptionalHeader, PE};
use serde_json::{json, Value as JsonValue};

use crate::error::Error;
use crate::formats::common::{
    extract_ascii_strings, extract_utf16_strings, hex_encode, put_i64, put_str, put_u64,
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
    errors_out: &mut Errors,
) -> Result<(), Error> {
    // PE strings are scattered across `.rdata`, `.data`, and resources.
    // The full-file scan is cheap and captures content embedded outside
    // of `goblin`'s parsed regions (overlays, hand-crafted sections).
    extract_ascii_strings(bytes, strings);
    extract_utf16_strings(bytes, strings);

    // Try the full goblin parse first — it gives us imports, exports,
    // resources, and the section table in one go. If it fails
    // (packed/obfuscated PE, malformed import directory, …) we fall
    // back to the header-only parse so we can still emit COFF +
    // optional-header + Authenticode facts. Partial output is far
    // more useful than none.
    //
    // `goblin_safe::parse_pe` validates the header up-front (rejects
    // PEs whose section count or directory-table sizes would blow up
    // goblin's lazy walkers), catches any panic from the parse, and
    // does the strict→permissive fallback internally. Callers must
    // never reach for `PE::parse_with_opts` directly.
    let parse_outcome = goblin_safe::parse_pe(bytes);
    // Record the failure mode (if any) into the structured errors
    // view *before* we attempt the header-only fallback, so consumers
    // can see exactly which sub-stage tripped even when the fallback
    // succeeds.
    match &parse_outcome {
        goblin_safe::GoblinOutcome::Failed(e) => {
            errors_out.record_malformed("pe-parse", e.to_string());
            metrics.insert("pe.parse_failed", 1.0);
        }
        goblin_safe::GoblinOutcome::Panicked(msg) => {
            errors_out.record_panic("pe-parse", msg);
            metrics.insert("pe.parse_panicked", 1.0);
        }
        goblin_safe::GoblinOutcome::Ok(_) => {}
    }
    if let Some(pe) = parse_outcome.ok() {
        coff_header(&pe.header.coff_header, values);
        if let Some(ref opt) = pe.header.optional_header {
            optional_header(opt, values);
            binary_flags(opt, metrics);
        }
        sections(&pe, bytes, metrics, sections_out);
        imports(&pe, values, metrics, imports_out);
        exports(&pe, values, metrics, exports_out);
        authenticode(&pe, bytes, values);
        if let Some(rd) = pe.resource_data.as_ref() {
            // The resource walker is lazy and slices with unchecked
            // header offsets — packed Windows malware regularly
            // panics inside `entries()` / `count()`. Wrap the walk
            // in catch_infallible so a malformed resource directory
            // leaves resource metrics at their defaults instead of
            // aborting the whole extraction.
            let walk = goblin_safe::catch_infallible(|| {
                resource_types(rd, values, metrics);
                resource_timestamp(rd, values);
                if let Some(ref vi) = rd.version_info {
                    super::pe_version_info::extract(vi, values);
                }
                if let Some(ref md) = rd.manifest_data {
                    super::pe_manifest::extract(md.data, values);
                }
            });
            if let goblin_safe::GoblinOutcome::Panicked(msg) = walk {
                errors_out.record_panic("pe-resource-walk", msg);
                metrics.insert("pe.resource_walk_panicked", 1.0);
            }
        }
        if let Some(ref dbg) = pe.debug_data {
            super::pe_debug::extract(dbg, values);
        }
        bound_imports(&pe, bytes, values);
        tls_callbacks(&pe, values, metrics);
        inflated_sections(&pe, values);
        load_config(&pe, values);
        super::pe_rich::extract(bytes, values);
        super::build_toolchain::from_pe_rich(values);
        return Ok(());
    }

    // Header-only fallback. The header parse is far more tolerant —
    // we can still surface machine / subsystem / characteristics +
    // Authenticode for binaries whose import directory is malformed
    // or stripped (packed installers, Go binaries, obfuscated builds).
    let header = goblin::pe::header::Header::parse(bytes)
        .map_err(|e| Error::malformed("pe", e.to_string()))?;
    coff_header(&header.coff_header, values);
    if let Some(ref opt) = header.optional_header {
        optional_header(opt, values);
        binary_flags(opt, metrics);
    }
    authenticode_from_header(&header, bytes, values);
    // Header-only fallback ran. Record that as a structured
    // fallback entry alongside the legacy `pe.partial_parse` bool
    // so trait authors can branch on either path. The bool is
    // retained as the canonical "is this a partial parse?" key for
    // existing rules.
    values.insert("pe.partial_parse", serde_json::Value::Bool(true));
    errors_out.record_fallback("pe-parse", "header-only fallback");
    metrics.insert("pe.partial_parse", 1.0);
    Ok(())
}

fn coff_header(coff: &CoffHeader, values: &mut Values) {
    // COFF/Optional-header fields land directly under `pe.*` — the
    // Win32 spec's two-header partitioning is internal plumbing the
    // forensic consumer doesn't need to navigate. `pe.machine` /
    // `pe.subsystem` / `pe.image_base` is what every Windows security
    // analyst reads.
    put_str(values, "pe.machine", machine_string(coff.machine));
    // PE's `TimeDateStamp` is a 32-bit Unix timestamp. Treat it as `i64`
    // for room beyond 2038 in case implementations decide to ignore the
    // signed/unsigned ambiguity. `sections.count` already exposes the
    // section count from a separate path; the COFF NumberOfSections
    // field would just duplicate it.
    put_i64(values, "pe.timestamp", i64::from(coff.time_date_stamp));
    let characteristics: Vec<JsonValue> = coff_characteristics(coff.characteristics)
        .into_iter()
        .map(|s| JsonValue::String(s.into()))
        .collect();
    values.insert("pe.characteristics", JsonValue::Array(characteristics));
}

fn optional_header(opt: &OptionalHeader, values: &mut Values) {
    let standard = &opt.standard_fields;
    let windows = &opt.windows_fields;

    put_str(values, "pe.subsystem", subsystem_string(windows.subsystem));
    put_u64(values, "pe.image_base", windows.image_base);
    put_u64(values, "pe.image_size", u64::from(windows.size_of_image));
    put_u64(values, "pe.headers_size", u64::from(windows.size_of_headers));
    put_u64(
        values,
        "pe.entry_point",
        u64::from(standard.address_of_entry_point),
    );
    put_str(
        values,
        "pe.subsystem_version",
        format!(
            "{}.{}",
            windows.major_subsystem_version, windows.minor_subsystem_version
        ),
    );
    put_str(
        values,
        "pe.os_version",
        format!(
            "{}.{}",
            windows.major_operating_system_version,
            windows.minor_operating_system_version
        ),
    );
    let dll_chars: Vec<JsonValue> = dll_characteristics(windows.dll_characteristics)
        .into_iter()
        .map(|s| JsonValue::String(s.into()))
        .collect();
    values.insert("pe.dll_characteristics", JsonValue::Array(dll_chars));
}

/// Cross-format `binary.is_pie` derivation for PE. ASLR opt-in via
/// `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x0040)` is the closest
/// equivalent: without it the loader fixes the image at `image_base`.
fn binary_flags(opt: &OptionalHeader, metrics: &mut Metrics) {
    let is_pie = opt.windows_fields.dll_characteristics & 0x0040 != 0;
    metrics.insert("binary.is_pie", f64::from(u8::from(is_pie)));
}

fn sections(pe: &PE<'_>, bytes: &[u8], metrics: &mut Metrics, sections_out: &mut Vec<Section>) {
    for (idx, section) in pe.sections.iter().enumerate() {
        let name = section.name().unwrap_or("").to_owned();
        let file_offset = u64::from(section.pointer_to_raw_data);
        let file_size = u64::from(section.size_of_raw_data);
        if file_size > 0 {
            let e = section_entropy(bytes, file_offset, file_size);
            metrics.insert(format!("sections[{idx}].entropy"), e);
        }
        sections_out.push(Section {
            name,
            vaddr: u64::from(section.virtual_address),
            vsize: u64::from(section.virtual_size),
            file_offset,
            file_size,
            flags: section_characteristics(section.characteristics)
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

/// Compute the canonical *imphash* — MD5 of the comma-joined,
/// lowercased `library.function` list, with `.dll`/`.ocx`/`.sys`
/// extensions stripped from the library name and IAT order
/// preserved.
///
/// The hash was popularised by Mandiant and remains the standard
/// per-import-table fingerprint for malware-family clustering.
/// Returns `None` when the import table is empty.
fn imphash(pe: &PE<'_>) -> Option<String> {
    use md5::{Digest, Md5};

    if pe.imports.is_empty() {
        return None;
    }
    let mut parts: Vec<String> = Vec::with_capacity(pe.imports.len());
    for imp in &pe.imports {
        let lib_raw = imp.dll.to_ascii_lowercase();
        let lib = strip_lib_ext(&lib_raw);
        let func = imp.name.to_ascii_lowercase();
        parts.push(format!("{lib}.{func}"));
    }
    let joined = parts.join(",");
    let digest = Md5::digest(joined.as_bytes());
    Some(hex_encode(&digest))
}

fn strip_lib_ext(lib: &str) -> &str {
    // Mandiant's spec strips `.dll`, `.ocx`, and `.sys`. Anything
    // else is preserved verbatim.
    for ext in [".dll", ".ocx", ".sys"] {
        if let Some(stem) = lib.strip_suffix(ext) {
            return stem;
        }
    }
    lib
}

fn imports(
    pe: &PE<'_>,
    values: &mut Values,
    metrics: &mut Metrics,
    imports_out: &mut crate::Imports,
) {
    // goblin's `imports` is flat: one entry per imported symbol with the
    // DLL name attached. Group by DLL for the public schema — that's
    // what tooling expects and matches `dumpbin /imports` output.
    use std::collections::BTreeMap;
    let mut by_dll: BTreeMap<String, Vec<JsonValue>> = BTreeMap::new();
    for imp in &pe.imports {
        by_dll
            .entry(imp.dll.to_string())
            .or_default()
            .push(JsonValue::String(imp.name.to_string()));
        // Mirror into the typed unified view. Library is normalised
        // to the lowercase stem (no `.dll` / `.ocx` / `.sys`) so
        // consumers can match against `library == "kernel32"` without
        // case- or extension-juggling. goblin synthesises the name
        // `ORDINAL N` for ordinal-only imports — surface the ordinal
        // explicitly in that case so consumers don't have to parse
        // the name back out.
        let lib_lower = imp.dll.to_ascii_lowercase();
        let library = strip_lib_ext(&lib_lower).to_string();
        let name_is_ordinal_stub = imp.name.starts_with("ORDINAL ");
        imports_out.push(crate::Import {
            name: imp.name.to_string(),
            library: Some(library),
            source: "pe",
            offset: Some(imp.offset as u64),
            ordinal: if name_is_ordinal_stub {
                Some(u32::from(imp.ordinal))
            } else {
                None
            },
        });
    }
    let arr: Vec<JsonValue> = by_dll
        .into_iter()
        .map(|(dll, functions)| {
            json!({
                "library": dll,
                "functions": functions,
            })
        })
        .collect();
    metrics.insert("pe.import_count", pe.imports.len() as f64);
    metrics.insert("pe.imported_library_count", arr.len() as f64);
    values.insert("pe.imports", JsonValue::Array(arr));

    if let Some(hash) = imphash(pe) {
        put_str(values, "pe.imphash", hash);
    }
}

fn exports(
    pe: &PE<'_>,
    values: &mut Values,
    metrics: &mut Metrics,
    exports_out: &mut crate::Exports,
) {
    let names: Vec<JsonValue> = pe
        .exports
        .iter()
        .filter_map(|e| e.name.map(|n| JsonValue::String(n.to_string())))
        .collect();
    for exp in &pe.exports {
        let Some(name) = exp.name else { continue };
        exports_out.push(crate::Export {
            name: name.to_string(),
            source: "pe",
            offset: exp.offset.map(|o| o as u64),
            ordinal: None,
        });
    }
    metrics.insert("pe.export_count", names.len() as f64);
    values.insert("pe.exports", JsonValue::Array(names));
}

/// Authenticode lookup using only the parsed header — used when the
/// full goblin parse fails and we fall back to a header-only walk.
///
/// The presence of `pe.signatures` (or its absence) IS the "is the
/// binary signed?" answer — we don't emit a redundant boolean for it.
/// When the cert-table directory is set but the bytes are truncated
/// or refuse to parse, no `pe.signatures` entry is emitted; consumers
/// distinguish "no signature claim" from "claimed but unparseable" via
/// the secondary `pe.cert_table_size` marker below.
fn authenticode_from_header(
    header: &goblin::pe::header::Header,
    bytes: &[u8],
    values: &mut Values,
) {
    let Some(opt) = header.optional_header.as_ref() else {
        return;
    };
    let Some(dir) = opt.data_directories.get_certificate_table() else {
        return;
    };
    if dir.size == 0 {
        return;
    }
    put_u64(values, "pe.cert_table_size", u64::from(dir.size));
    let offset = dir.virtual_address as usize;
    let size = dir.size as usize;
    if offset.saturating_add(size) > bytes.len() {
        return;
    }
    super::pe_authenticode::parse(&bytes[offset..offset + size], values);
}

fn authenticode(pe: &PE<'_>, bytes: &[u8], values: &mut Values) {
    // The Authenticode signature lives in the Certificate Table data
    // directory (entry index 4 in the optional header). The
    // directory's `virtual_address` is a *file offset* for this entry
    // (uniquely among PE directories), so we read the bytes directly.
    //
    // Presence/absence of `pe.signatures` is the canonical "is the
    // binary signed?" signal; we emit `pe.cert_table_size` whenever
    // the directory points at a non-empty blob so consumers can
    // distinguish "no signature at all" from "claimed but unparseable
    // signature" without a redundant boolean.
    let Some(opt) = pe.header.optional_header.as_ref() else {
        return;
    };
    let Some(dir) = opt.data_directories.get_certificate_table() else {
        return;
    };
    if dir.size == 0 {
        return;
    }
    put_u64(values, "pe.cert_table_size", u64::from(dir.size));
    let offset = dir.virtual_address as usize;
    let size = dir.size as usize;
    if offset.saturating_add(size) > bytes.len() {
        return;
    }
    super::pe_authenticode::parse(&bytes[offset..offset + size], values);
}

fn machine_string(machine: u16) -> &'static str {
    // Constants from winnt.h `IMAGE_FILE_MACHINE_*`.
    match machine {
        0x014c => "i386",
        0x0162 => "r3000",
        0x0166 => "r4000",
        0x0168 => "r10000",
        0x0169 => "wcemipsv2",
        0x0184 => "alpha",
        0x01a2 => "sh3",
        0x01a3 => "sh3dsp",
        0x01a6 => "sh4",
        0x01a8 => "sh5",
        0x01c0 => "arm",
        0x01c2 => "thumb",
        0x01c4 => "armnt",
        0x01d3 => "am33",
        0x01f0 => "powerpc",
        0x01f1 => "powerpcfp",
        0x0200 => "ia64",
        0x0266 => "mips16",
        0x0284 => "alpha64",
        0x0366 => "mipsfpu",
        0x0466 => "mipsfpu16",
        0x0520 => "tricore",
        0x0cef => "cef",
        0x0ebc => "ebc",
        0x8664 => "x86_64",
        0x9041 => "m32r",
        0xaa64 => "arm64",
        0xc0ee => "cee",
        _ => "unknown",
    }
}

fn coff_characteristics(flags: u16) -> Vec<&'static str> {
    // From winnt.h `IMAGE_FILE_*`. The forensically relevant subset; rare
    // legacy flags (DEBUG_STRIPPED, NET_RUN_FROM_SWAP) are omitted.
    let mut out = Vec::new();
    if flags & 0x0001 != 0 {
        out.push("relocs_stripped");
    }
    if flags & 0x0002 != 0 {
        out.push("executable_image");
    }
    if flags & 0x0020 != 0 {
        out.push("large_address_aware");
    }
    if flags & 0x0100 != 0 {
        out.push("32bit_machine");
    }
    if flags & 0x1000 != 0 {
        out.push("system_image");
    }
    if flags & 0x2000 != 0 {
        out.push("dll");
    }
    out
}

fn dll_characteristics(flags: u16) -> Vec<&'static str> {
    let mut out = Vec::new();
    if flags & 0x0020 != 0 {
        out.push("high_entropy_va");
    }
    if flags & 0x0040 != 0 {
        out.push("dynamic_base");
    }
    if flags & 0x0080 != 0 {
        out.push("force_integrity");
    }
    if flags & 0x0100 != 0 {
        out.push("nx_compat");
    }
    if flags & 0x0200 != 0 {
        out.push("no_isolation");
    }
    if flags & 0x0400 != 0 {
        out.push("no_seh");
    }
    if flags & 0x0800 != 0 {
        out.push("no_bind");
    }
    if flags & 0x1000 != 0 {
        out.push("app_container");
    }
    if flags & 0x2000 != 0 {
        out.push("wdm_driver");
    }
    if flags & 0x4000 != 0 {
        out.push("guard_cf");
    }
    if flags & 0x8000 != 0 {
        out.push("terminal_server_aware");
    }
    out
}

fn subsystem_string(subsystem: u16) -> &'static str {
    // From winnt.h `IMAGE_SUBSYSTEM_*`. `0` (the explicit "unknown"
    // constant) collapses into the default arm — same string, same
    // meaning, no semantic loss.
    match subsystem {
        1 => "native",
        2 => "windows_gui",
        3 => "windows_cui",
        5 => "os2_cui",
        7 => "posix_cui",
        8 => "native_windows",
        9 => "windows_ce_gui",
        10 => "efi_application",
        11 => "efi_boot_service_driver",
        12 => "efi_runtime_driver",
        13 => "efi_rom",
        14 => "xbox",
        16 => "windows_boot_application",
        _ => "unknown",
    }
}

fn section_characteristics(flags: u32) -> Vec<&'static str> {
    let mut out = Vec::new();
    if flags & 0x0000_0020 != 0 {
        out.push("code");
    }
    if flags & 0x0000_0040 != 0 {
        out.push("initialized_data");
    }
    if flags & 0x0000_0080 != 0 {
        out.push("uninitialized_data");
    }
    if flags & 0x2000_0000 != 0 {
        out.push("executable");
    }
    if flags & 0x4000_0000 != 0 {
        out.push("readable");
    }
    if flags & 0x8000_0000 != 0 {
        out.push("writable");
    }
    out
}

/// Walk the resource directory's top-level entries and surface the
/// `RT_*` type IDs as a list of strings. The first entry is the first
/// top-level type ordered by the linker, which `pe.resource_types[0]`
/// traits can match exactly (forensically meaningful: stub binaries
/// often emit only RT_VERSION + RT_MANIFEST and nothing else).
fn resource_types(
    rd: &goblin::pe::resource::ResourceData<'_>,
    values: &mut Values,
    metrics: &mut Metrics,
) {
    let mut names: Vec<JsonValue> = Vec::new();
    for entry in rd.entries().flatten() {
        if let Some(id) = entry.id() {
            names.push(JsonValue::String(rt_name(id).to_string()));
        }
    }
    metrics.insert("pe.resource_count", names.len() as f64);
    if !names.is_empty() {
        values.insert("pe.resource_types", JsonValue::Array(names));
    }
}

/// Map a top-level resource directory `id` to its `RT_*` constant
/// name. Unknown / vendor-private types collapse to `RT_UNKNOWN`.
fn rt_name(id: u16) -> &'static str {
    // From winuser.h `RT_*` and verrsrc.h. Covers every standard
    // Windows resource type Windows tooling generates.
    match id {
        1 => "RT_CURSOR",
        2 => "RT_BITMAP",
        3 => "RT_ICON",
        4 => "RT_MENU",
        5 => "RT_DIALOG",
        6 => "RT_STRING",
        7 => "RT_FONTDIR",
        8 => "RT_FONT",
        9 => "RT_ACCELERATOR",
        10 => "RT_RCDATA",
        11 => "RT_MESSAGETABLE",
        12 => "RT_GROUP_CURSOR",
        14 => "RT_GROUP_ICON",
        16 => "RT_VERSION",
        17 => "RT_DLGINCLUDE",
        19 => "RT_PLUGPLAY",
        20 => "RT_VXD",
        21 => "RT_ANICURSOR",
        22 => "RT_ANIICON",
        23 => "RT_HTML",
        24 => "RT_MANIFEST",
        _ => "RT_UNKNOWN",
    }
}

/// Parse the `IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT` table (data
/// directory index 11). Unlike every other data directory entry, the
/// `VirtualAddress` here is a **file offset**, not an RVA — the table
/// lives in the headers between the data directories and the section
/// table. Each `IMAGE_BOUND_IMPORT_DESCRIPTOR` is 8 bytes; an all-zero
/// descriptor terminates the list, and module-name offsets are
/// relative to the start of the bound-import table.
///
/// Bound-import tables are largely a 1990s artefact (the loader
/// rebinds on mismatch), so finding one is itself a build-pipeline
/// fingerprint.
fn bound_imports(pe: &PE<'_>, bytes: &[u8], values: &mut Values) {
    let Some(opt) = pe.header.optional_header.as_ref() else {
        return;
    };
    let Some(dd) = opt.data_directories.get_bound_import_table() else {
        return;
    };
    let table_off = dd.virtual_address as usize;
    let table_size = dd.size as usize;
    if table_size == 0 || table_off >= bytes.len() {
        return;
    }
    let end = table_off.saturating_add(table_size).min(bytes.len());
    let table = &bytes[table_off..end];

    let mut modules: Vec<JsonValue> = Vec::new();
    let mut cursor = 0_usize;
    while cursor + 8 <= table.len() {
        let time_date = u32::from_le_bytes(table[cursor..cursor + 4].try_into().unwrap());
        let name_off = u16::from_le_bytes(table[cursor + 4..cursor + 6].try_into().unwrap()) as usize;
        let forwarder_count =
            u16::from_le_bytes(table[cursor + 6..cursor + 8].try_into().unwrap()) as usize;

        // All-zero descriptor terminates the list.
        if time_date == 0 && name_off == 0 && forwarder_count == 0 {
            break;
        }

        if name_off < table.len() {
            // Module name is a NUL-terminated ASCII string at table[name_off..].
            let tail = &table[name_off..];
            let len = tail.iter().position(|b| *b == 0).unwrap_or(tail.len());
            if let Ok(name) = std::str::from_utf8(&tail[..len]) {
                if !name.is_empty() {
                    modules.push(JsonValue::String(name.to_string()));
                }
            }
        }

        // Skip this descriptor + its forwarder-ref records (each 8 bytes).
        cursor = cursor.saturating_add(8 + forwarder_count.saturating_mul(8));
    }
    if !modules.is_empty() {
        values.insert("pe.bound_imports", JsonValue::Array(modules));
    }
}

/// Walk the TLS Directory's `AddressOfCallBacks` table and surface the
/// callback function VAs. TLS callbacks are the Windows analog of ELF
/// `.init_array`; they run before `main()` and are a classic
/// anti-analysis hook point (malware uses them to defeat
/// breakpoint-on-entry debuggers). When a callback VA matches an
/// export, the export name is included alongside the address.
fn tls_callbacks(pe: &PE<'_>, values: &mut Values, metrics: &mut Metrics) {
    let Some(tls) = pe.tls_data.as_ref() else {
        return;
    };
    if tls.callbacks.is_empty() {
        return;
    }
    metrics.insert("pe.tls_callback_count", tls.callbacks.len() as f64);

    let export_by_va: std::collections::HashMap<u64, &str> = pe
        .exports
        .iter()
        .filter_map(|e| {
            // `e.rva` is the export RVA; turn it into a VA by adding
            // the image base for symbol-attribution lookup against the
            // TLS callback table (which is stored as VAs).
            let va = pe
                .header
                .optional_header
                .as_ref()
                .map(|h| h.windows_fields.image_base.saturating_add(e.rva as u64))?;
            e.name.map(|n| (va, n))
        })
        .collect();

    let entries: Vec<JsonValue> = tls
        .callbacks
        .iter()
        .map(|addr| {
            let mut node = serde_json::Map::new();
            node.insert("addr".into(), JsonValue::String(format!("0x{addr:x}")));
            if let Some(name) = export_by_va.get(addr) {
                node.insert("symbol".into(), JsonValue::String((*name).to_string()));
            }
            JsonValue::Object(node)
        })
        .collect();
    values.insert("pe.tls_callbacks", JsonValue::Array(entries));
}

/// List PE section names whose `VirtualSize` significantly exceeds
/// their `SizeOfRawData` — the classic packer fingerprint, since the
/// runtime decompresses payload bytes into a much larger memory image.
/// Threshold matches the cleave-traits convention: virtual ≥ 4× raw.
fn inflated_sections(pe: &PE<'_>, values: &mut Values) {
    let names: Vec<JsonValue> = pe
        .sections
        .iter()
        .filter_map(|s| {
            let vsize = u64::from(s.virtual_size);
            let rsize = u64::from(s.size_of_raw_data);
            if rsize == 0 || vsize <= rsize.saturating_mul(4) {
                return None;
            }
            s.name().ok().map(|n| JsonValue::String(n.to_string()))
        })
        .collect();
    if !names.is_empty() {
        values.insert("pe.inflated_sections", JsonValue::Array(names));
    }
}

/// Decompose the Load Configuration Directory's `guard_flags` field
/// into the named `IMAGE_GUARD_*` bits. These flags describe how
/// Control Flow Guard / Return Flow Guard hardening was wired up at
/// link time; analysts use them to distinguish compiler-enforced
/// indirect-call protection from binaries that opted out.
fn load_config(pe: &PE<'_>, values: &mut Values) {
    let Some(lc) = pe.load_config_data.as_ref() else {
        return;
    };
    let Some(guard_flags) = lc.directory.guard_flags else {
        return;
    };
    let names = guard_flag_names(guard_flags);
    if names.is_empty() {
        return;
    }
    let mut obj = serde_json::Map::new();
    obj.insert(
        "guard_flags".into(),
        JsonValue::Array(
            names
                .into_iter()
                .map(|s| JsonValue::String(s.to_string()))
                .collect(),
        ),
    );
    values.insert("pe.load_config", JsonValue::Object(obj));
}

/// `IMAGE_GUARD_*` constants from `winnt.h`. Names follow the
/// Microsoft-published abbreviations (sans `IMAGE_GUARD_` prefix,
/// lowercased) so analysts can `exact:` against the flag directly.
fn guard_flag_names(flags: u32) -> Vec<&'static str> {
    let mut out = Vec::new();
    if flags & 0x0000_0100 != 0 {
        out.push("cf_instrumented");
    }
    if flags & 0x0000_0200 != 0 {
        out.push("cfw_instrumented");
    }
    if flags & 0x0000_0400 != 0 {
        out.push("function_table_present");
    }
    if flags & 0x0000_0800 != 0 {
        out.push("security_cookie_unused");
    }
    if flags & 0x0001_0000 != 0 {
        out.push("protect_delayload_iat");
    }
    if flags & 0x0002_0000 != 0 {
        out.push("delayload_iat_in_its_own_section");
    }
    if flags & 0x0004_0000 != 0 {
        out.push("export_suppression_info_present");
    }
    if flags & 0x0008_0000 != 0 {
        out.push("enable_export_suppression");
    }
    if flags & 0x0010_0000 != 0 {
        out.push("longjump_table_present");
    }
    if flags & 0x4000_0000 != 0 {
        out.push("rf_instrumented");
    }
    if flags & 0x8000_0000 != 0 {
        out.push("rf_enable");
    }
    out
}

/// `IMAGE_RESOURCE_DIRECTORY.TimeDateStamp` — independent of the COFF
/// `TimeDateStamp`, set by the resource compiler at link time. Often
/// left untouched across rebuilds, so a change between releases of an
/// otherwise-stable binary is a tampering signal.
fn resource_timestamp(rd: &goblin::pe::resource::ResourceData<'_>, values: &mut Values) {
    let ts = rd.image_resource_directory.time_date_stamp;
    if ts != 0 {
        put_u64(values, "pe.resource_timestamp", u64::from(ts));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rt_name_known() {
        assert_eq!(rt_name(16), "RT_VERSION");
        assert_eq!(rt_name(24), "RT_MANIFEST");
        assert_eq!(rt_name(3), "RT_ICON");
        assert_eq!(rt_name(99), "RT_UNKNOWN");
    }

    #[test]
    fn machine_string_known_values() {
        assert_eq!(machine_string(0x8664), "x86_64");
        assert_eq!(machine_string(0x014c), "i386");
        assert_eq!(machine_string(0xaa64), "arm64");
        assert_eq!(machine_string(0xffff), "unknown");
    }

    #[test]
    fn dll_characteristics_bit_decomposition() {
        // dynamic_base | nx_compat | high_entropy_va
        let flags = 0x0040 | 0x0100 | 0x0020;
        let chars = dll_characteristics(flags);
        assert!(chars.contains(&"dynamic_base"));
        assert!(chars.contains(&"nx_compat"));
        assert!(chars.contains(&"high_entropy_va"));
    }

    #[test]
    fn subsystem_string_known_values() {
        assert_eq!(subsystem_string(2), "windows_gui");
        assert_eq!(subsystem_string(3), "windows_cui");
        assert_eq!(subsystem_string(1), "native");
    }

    fn run(bytes: &[u8]) -> (Values, Strings, Metrics) {
        let mut v = Values::new();
        let mut s = Strings::default();
        let mut m = Metrics::new();
        let mut sections = Vec::new();
        let mut imports = crate::Imports::new();
        let mut exports = crate::Exports::new();
        let mut errors = Errors::new();
        let _ = extract(
            bytes,
            &mut v,
            &mut s,
            &mut m,
            &mut sections,
            &mut imports,
            &mut exports,
            &mut errors,
        );
        (v, s, m)
    }

    fn read_fixture(name: &str) -> Vec<u8> {
        let path = format!("../cleave/tests/fixtures/{name}");
        std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {path}: {e}"))
    }

    #[test]
    fn dll_characteristics_empty_when_zero() {
        let chars = dll_characteristics(0);
        assert!(chars.is_empty());
    }

    #[test]
    fn dll_characteristics_picks_up_force_integrity_and_aslr() {
        // force_integrity (0x80) | dynamic_base (0x40) | guard_cf (0x4000)
        let chars = dll_characteristics(0x80 | 0x40 | 0x4000);
        assert!(chars.contains(&"force_integrity"));
        assert!(chars.contains(&"dynamic_base"));
        assert!(chars.contains(&"guard_cf"));
    }

    #[test]
    fn subsystem_string_unknown_fallback() {
        assert_eq!(subsystem_string(99), "unknown");
    }

    #[test]
    fn rt_name_covers_canonical_resource_types() {
        assert_eq!(rt_name(1), "RT_CURSOR");
        assert_eq!(rt_name(2), "RT_BITMAP");
        assert_eq!(rt_name(14), "RT_GROUP_ICON");
    }

    #[test]
    fn empty_input_doesnt_crash() {
        let (_, _, _) = run(&[]);
    }

    #[test]
    fn non_pe_input_is_rejected_silently() {
        let (v, _, m) = run(b"\x00\x00\x00 not even MZ");
        assert!(v.is_empty() || v.get("pe.coff").is_none());
        assert!(m.get("binary.is_pie").is_none());
    }

    #[test]
    fn truncated_pe_header_doesnt_crash() {
        let mut bytes = vec![0u8; 64];
        bytes[..2].copy_from_slice(b"MZ");
        let (_, _, _) = run(&bytes);
    }

    #[test]
    fn end_to_end_parses_real_pe_fixture() {
        let bytes = read_fixture("test.exe");
        let (v, _, m) = run(&bytes);
        // Pike-style flat schema for COFF + optional header.
        assert!(v.get("pe.coff").is_some() || v.get("pe.machine").is_some());
        // PIE flag derived from DLL_CHARACTERISTICS_DYNAMIC_BASE.
        assert!(m.get("binary.is_pie").is_some());
    }

    /// Verifies the typed Imports/Exports views are populated in
    /// lockstep with the legacy `pe.imports[]` / `pe.exports[]` kv
    /// shape, and that library names are normalised (lowercase, no
    /// `.dll`).
    #[test]
    fn typed_imports_and_exports_populated() {
        let bytes = read_fixture("test.exe");
        let mut v = Values::new();
        let mut s = Strings::default();
        let mut m = Metrics::new();
        let mut sections = Vec::new();
        let mut imports = crate::Imports::new();
        let mut exports = crate::Exports::new();
        let mut errors = Errors::new();
        extract(
            &bytes,
            &mut v,
            &mut s,
            &mut m,
            &mut sections,
            &mut imports,
            &mut exports,
            &mut errors,
        )
        .unwrap();
        assert!(!imports.is_empty(), "expected at least one PE import");
        for imp in imports.iter() {
            assert_eq!(imp.source, "pe");
            let lib = imp.library.as_deref().expect("PE imports carry library");
            assert_eq!(lib, &lib.to_ascii_lowercase());
            assert!(
                !lib.ends_with(".dll") && !lib.ends_with(".ocx") && !lib.ends_with(".sys"),
                "library stem should drop extension: {lib}",
            );
        }
    }
}
