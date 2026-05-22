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
    extract_binary_strings, extract_utf16_strings, hex_encode, put_i64, put_str, put_u64,
    rizin_fallback_with_sections,
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
    // PE strings are scattered across `.rdata`, `.data`, and resources.
    // The full-file scan is cheap and captures content embedded outside
    // of `goblin`'s parsed regions (overlays, hand-crafted sections).
    extract_binary_strings(bytes, strings);
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
        dos_header(&pe.header, values);
        if let Some(ref opt) = pe.header.optional_header {
            optional_header(opt, values);
            binary_flags(opt, metrics);
        }
        sections(&pe, bytes, metrics, sections_out);
        imports(&pe, values, metrics, imports_out);
        exports(&pe, values, metrics, exports_out);
        authenticode(&pe, bytes, values, metrics);
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
                // Presence flags emitted authoritatively from the
                // resource directory walker — distinct from whether
                // the version/manifest extraction populated any
                // downstream keys (which can be empty on malformed
                // structures).
                if rd.version_info.is_some() {
                    metrics.insert("pe.has_version_info", 1.0);
                }
                if rd.manifest_data.is_some() {
                    metrics.insert("pe.has_manifest", 1.0);
                }
                // Count icon entries — IMAGE_RESOURCE RT_ICON (3) +
                // RT_GROUP_ICON (14) — separately so consumers can
                // distinguish "icon presence" from total resource count.
                let icon_count = rd
                    .entries()
                    .flatten()
                    .filter(|e| matches!(e.id(), Some(3 | 14)))
                    .count() as f64;
                if icon_count > 0.0 {
                    metrics.insert("pe.icon_count", icon_count);
                }
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
        bound_imports_with_metrics(&pe, bytes, values, metrics);
        tls_callbacks(&pe, values, metrics);
        inflated_sections(&pe, values);
        load_config(&pe, values);
        entry_and_overlay(&pe, bytes, values, metrics);
        section_anomalies(&pe, bytes, values, metrics);
        dos_stub_anomalies(&pe, bytes, metrics);
        checksum(&pe, bytes, metrics);
        aliased_exports(&pe, bytes, metrics);
        clr_metadata(&pe, values);
        data_directories(&pe, values);
        super::pe_image_hash::extract(&pe, bytes, values, metrics);
        super::pe_rich::extract(bytes, values);
        super::build_toolchain::from_pe_rich(values);
        rizin_fallback_with_sections(
            bytes,
            imports_out,
            exports_out,
            functions_out,
            sections_out,
            metrics,
            "pe",
        );
        return Ok(());
    }

    // Header-only fallback. The header parse is far more tolerant —
    // we can still surface machine / subsystem / characteristics +
    // Authenticode for binaries whose import directory is malformed
    // or stripped (packed installers, Go binaries, obfuscated builds).
    let header = goblin::pe::header::Header::parse(bytes)
        .map_err(|e| Error::malformed("pe", e.to_string()))?;
    coff_header(&header.coff_header, values);
    dos_header(&header, values);
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
    // Raw COFF machine + characteristics u16 values. Stable across
    // PE revisions and what downstream code that needs to round-trip
    // back to goblin's typed bitmasks looks at — distinct from the
    // string-flag projections above.
    put_u64(values, "pe.machine_id", u64::from(coff.machine));
    put_u64(
        values,
        "pe.characteristics_raw",
        u64::from(coff.characteristics),
    );
    // PE's `TimeDateStamp` is a 32-bit Unix timestamp. Treat it as `i64`
    // for room beyond 2038 in case implementations decide to ignore the
    // signed/unsigned ambiguity. `sections.count` already exposes the
    // section count from a separate path; the COFF NumberOfSections
    // field would just duplicate it.
    put_i64(values, "pe.timestamp", i64::from(coff.time_date_stamp));
    // COFF symbol-table pointer + entry count. Modern toolchains zero
    // both (debug info goes to PDBs), so a non-zero pair flags an
    // older or unusual build. Consumers compute `has_coff_symbols`
    // from `pst != 0 && nst != 0`.
    put_u64(
        values,
        "pe.coff.symbol_table_offset",
        u64::from(coff.pointer_to_symbol_table),
    );
    put_u64(
        values,
        "pe.coff.number_of_symbol_table",
        u64::from(coff.number_of_symbol_table),
    );
    let characteristics: Vec<JsonValue> = coff_characteristics(coff.characteristics)
        .into_iter()
        .map(|s| JsonValue::String(s.into()))
        .collect();
    values.insert("pe.characteristics", JsonValue::Array(characteristics));
}

/// DOS-header fields downstream consumers need. Currently just
/// `e_lfanew` (the offset to the PE signature) so cleave can locate
/// the Rich Header region without re-parsing.
fn dos_header(header: &goblin::pe::header::Header, values: &mut Values) {
    put_u64(
        values,
        "pe.coff.dos_header_pe_pointer",
        u64::from(header.dos_header.pe_pointer),
    );
}

fn optional_header(opt: &OptionalHeader, values: &mut Values) {
    let standard = &opt.standard_fields;
    let windows = &opt.windows_fields;

    put_str(values, "pe.subsystem", subsystem_string(windows.subsystem));
    put_u64(values, "pe.image_base", windows.image_base);
    put_u64(values, "pe.image_size", u64::from(windows.size_of_image));
    put_u64(
        values,
        "pe.headers_size",
        u64::from(windows.size_of_headers),
    );
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
            windows.major_operating_system_version, windows.minor_operating_system_version
        ),
    );
    // Raw optional-header u16/u32 fields. Cleave consumes the numeric
    // forms; the string projections above are for human-facing tools.
    put_u64(values, "pe.subsystem_raw", u64::from(windows.subsystem));
    put_u64(
        values,
        "pe.dll_characteristics_raw",
        u64::from(windows.dll_characteristics),
    );
    put_u64(
        values,
        "pe.file_alignment",
        u64::from(windows.file_alignment),
    );
    put_u64(
        values,
        "pe.section_alignment",
        u64::from(windows.section_alignment),
    );
    put_u64(
        values,
        "pe.linker_major_version",
        u64::from(standard.major_linker_version),
    );
    put_u64(
        values,
        "pe.linker_minor_version",
        u64::from(standard.minor_linker_version),
    );
    put_u64(
        values,
        "pe.number_of_rva_and_sizes",
        u64::from(windows.number_of_rva_and_sizes),
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
        // Raw IMAGE_SCN_* characteristics bitmask — emitted positionally
        // so downstream consumers can reconstruct the typed u32 without
        // a reverse-lookup over the string-flag projection.
        metrics.insert(
            format!("sections[{idx}].characteristics"),
            f64::from(section.characteristics),
        );
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
    // Total import-symbol count flows through cross-format `imports.count`.
    // DLL dependencies (the libraries imports are bound to) flow through
    // cross-format `dependencies.count`.
    metrics.insert("dependencies.count", arr.len() as f64);
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
    let mut forwarded_count: u32 = 0;
    for exp in &pe.exports {
        let Some(name) = exp.name else { continue };
        // PE forwarded exports come in two shapes (per
        // `IMAGE_EXPORT_DIRECTORY` §6.3.1): `DLL.symbol` and
        // `DLL.#ordinal`. Both are serialised back into a single
        // string so consumers don't have to switch on a
        // discriminator. When the entry is a normal export
        // (RVA points at this binary's own code/data), `forward_to`
        // stays `None`.
        let forward_to = match exp.reexport {
            Some(goblin::pe::export::Reexport::DLLName { export, lib }) => {
                forwarded_count = forwarded_count.saturating_add(1);
                Some(format!("{lib}.{export}"))
            }
            Some(goblin::pe::export::Reexport::DLLOrdinal { ordinal, lib }) => {
                forwarded_count = forwarded_count.saturating_add(1);
                Some(format!("{lib}.#{ordinal}"))
            }
            None => None,
        };
        // We emit the RVA (image-relative virtual address) rather
        // than the on-disk file offset because RVA is what every
        // analyst-facing tool shows — `dumpbin /exports`, IDA,
        // Ghidra, and the PE specification all key exports off
        // RVA. The file offset is internal plumbing and not
        // forensically interesting for an export-table consumer.
        exports_out.push(crate::Export {
            name: name.to_string(),
            source: "pe",
            offset: Some(exp.rva as u64),
            ordinal: None,
            forward_to,
        });
    }
    // Export count flows through cross-format `exports.count`.
    if forwarded_count > 0 {
        metrics.insert("pe.forwarded_export_count", f64::from(forwarded_count));
    }
    // Export-directory timestamp lives inside IMAGE_EXPORT_DIRECTORY
    // and is distinct from the COFF header's `pe.timestamp`. Supply-
    // chain tampering sometimes rewrites one without touching the
    // other, so emit it independently. Zero is a sentinel meaning
    // "unset" — linkers can elect to leave it untouched.
    if let Some(export_data) = &pe.export_data {
        let ts = export_data.export_directory_table.time_date_stamp;
        if ts != 0 {
            put_i64(values, "pe.export_timestamp", i64::from(ts));
        }
    }
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

fn authenticode(pe: &PE<'_>, bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
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
    // The security-directory virtual_address is supposed to be an
    // in-file offset (PE/COFF spec carves an exception for the
    // Certificate Table). When the bytes it points at fall outside
    // the file, the header has been tampered with — emit a flag so
    // downstream callers don't have to redo the bounds check.
    if offset > 0 && offset.saturating_add(size) > bytes.len() {
        metrics.insert("pe.security_directory_out_of_bounds", 1.0);
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
    // Resource count is the raw entry total — duplicates allowed.
    let total = rd.entries().flatten().count() as f64;
    metrics.insert("pe.resource_count", total);

    // `pe.resource_types[]` is a *deduplicated, sorted by numeric id*
    // list of canonical `RT_*` names. Sorting on the numeric id (not
    // the string) keeps the ordering stable across rt_name's
    // unknown-id fallback, which collapses many ids to "RT_UNKNOWN".
    let mut type_ids: std::collections::BTreeSet<u16> = std::collections::BTreeSet::new();
    for entry in rd.entries().flatten() {
        if let Some(id) = entry.id() {
            type_ids.insert(id);
        }
    }
    if !type_ids.is_empty() {
        let names: Vec<JsonValue> = type_ids
            .iter()
            .map(|&id| JsonValue::String(rt_name(id).to_string()))
            .collect();
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
/// `bound_imports_with_metrics` emits the directory. The lazy goblin walker
/// can panic on truncated tables, so we keep the parse self-contained
/// (we already validated the directory bounds before calling).
///
/// Emits to values:
/// - `pe.bound_imports[]` — array of `{name, time_date_stamp,
///   forwarder_ref_count}` objects, capped at 64 entries.
///
/// Emits to metrics when present:
/// - `pe.bound_import_count` — number of descriptors recovered.
/// - `pe.bound_imports_fingerprint` — CRC-32 of the canonical-sorted
///   set. Useful for "binaries linked on the same host within seconds
///   get the same fingerprint" clustering.
fn bound_imports_with_metrics(
    pe: &PE<'_>,
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
) {
    bound_imports_inner(pe, bytes, values, Some(metrics));
}

fn bound_imports_inner(
    pe: &PE<'_>,
    bytes: &[u8],
    values: &mut Values,
    metrics: Option<&mut Metrics>,
) {
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

    struct Desc {
        name: String,
        time_date_stamp: u32,
        forwarder_ref_count: u32,
    }
    let mut out: Vec<Desc> = Vec::new();
    let mut cursor = 0_usize;
    while cursor + 8 <= table.len() && out.len() < 64 {
        let time_date = u32::from_le_bytes(table[cursor..cursor + 4].try_into().unwrap());
        let name_off =
            u16::from_le_bytes(table[cursor + 4..cursor + 6].try_into().unwrap()) as usize;
        let forwarder_count =
            u16::from_le_bytes(table[cursor + 6..cursor + 8].try_into().unwrap()) as u32;

        // All-zero descriptor terminates the list.
        if time_date == 0 && name_off == 0 && forwarder_count == 0 {
            break;
        }
        if name_off < table.len() {
            let tail = &table[name_off..table.len().min(name_off + 256)];
            let len = tail.iter().position(|b| *b == 0).unwrap_or(tail.len());
            if let Ok(name) = std::str::from_utf8(&tail[..len]) {
                if !name.is_empty() {
                    out.push(Desc {
                        name: name.to_string(),
                        time_date_stamp: time_date,
                        forwarder_ref_count: forwarder_count,
                    });
                }
            }
        }
        cursor = cursor.saturating_add(8 + (forwarder_count as usize).saturating_mul(8));
    }
    if out.is_empty() {
        return;
    }

    let modules: Vec<JsonValue> = out
        .iter()
        .map(|d| {
            serde_json::json!({
                "name": d.name,
                "time_date_stamp": d.time_date_stamp,
                "forwarder_ref_count": d.forwarder_ref_count,
            })
        })
        .collect();
    values.insert("pe.bound_imports", JsonValue::Array(modules));

    if let Some(metrics) = metrics {
        metrics.insert("pe.bound_import_count", out.len() as f64);
        // CRC-32 fingerprint over the canonical-sorted set so the
        // linker's emission order doesn't change clustering.
        let mut sorted: Vec<&Desc> = out.iter().collect();
        sorted.sort_by(|a, b| a.name.cmp(&b.name));
        let mut hasher = crc32fast::Hasher::new();
        for d in sorted {
            hasher.update(d.name.as_bytes());
            hasher.update(&[0]);
            hasher.update(&d.time_date_stamp.to_le_bytes());
            hasher.update(&d.forwarder_ref_count.to_le_bytes());
        }
        metrics.insert("pe.bound_imports_fingerprint", f64::from(hasher.finalize()));
    }
}

/// Walk the TLS Directory's `AddressOfCallBacks` table and surface the
/// callback function VAs. TLS callbacks are the Windows analog of ELF
/// `.init_array`; they run before `main()` and are a classic
/// anti-analysis hook point (malware uses them to defeat
/// breakpoint-on-entry debuggers). When a callback VA matches an
/// export, the export name is included alongside the address.
/// PE optional-header data directories — the 16-slot table that
/// indexes the special directories (export, import, resource, …) by
/// RVA + size. Emits non-zero slots as `pe.data_directories[]` so
/// downstream consumers can drive lookups off canonical names rather
/// than fixed indices.
fn data_directories(pe: &PE<'_>, values: &mut Values) {
    let Some(opt) = pe.header.optional_header.as_ref() else {
        return;
    };
    // Index → canonical name from the PE/COFF spec
    // (winnt.h IMAGE_DIRECTORY_ENTRY_*).
    const NAMES: [&str; 16] = [
        "export",
        "import",
        "resource",
        "exception",
        "certificate",
        "base_relocation",
        "debug",
        "architecture",
        "global_ptr",
        "tls",
        "load_config",
        "bound_import",
        "iat",
        "delay_import",
        "clr_runtime_header",
        "reserved",
    ];
    let mut entries: Vec<JsonValue> = Vec::new();
    for (idx, slot) in opt.data_directories.data_directories.iter().enumerate() {
        let Some((_, dir)) = slot.as_ref() else {
            continue;
        };
        if dir.virtual_address == 0 && dir.size == 0 {
            continue;
        }
        let name = NAMES.get(idx).copied().unwrap_or("unknown");
        entries.push(serde_json::json!({
            "name": name,
            "rva": dir.virtual_address,
            "size": dir.size,
        }));
    }
    if !entries.is_empty() {
        values.insert("pe.data_directories", JsonValue::Array(entries));
    }
}

/// .NET / CLR metadata extracted from the COR20 header. The presence
/// of `pe.clr` (or any sub-key) IS the "is this a managed binary?"
/// signal — distinct from PE Authenticode signing, which a managed
/// binary may or may not carry.
///
/// Emits:
/// - `pe.clr.runtime_version`  — `"<major>.<minor>"` runtime version string
/// - `pe.clr.is_il_only`       — 1 when the COMIMAGE_FLAGS_ILONLY bit is set
/// - `pe.clr.is_native_entrypoint` — 1 when COMIMAGE_FLAGS_NATIVE_ENTRYPOINT is set
fn clr_metadata(pe: &PE<'_>, values: &mut Values) {
    let Some(clr) = pe.clr_data.as_ref() else {
        return;
    };
    let hdr = &clr.cor20_header;
    crate::formats::common::put_str(
        values,
        "pe.clr.runtime_version",
        format!(
            "{}.{}",
            hdr.major_runtime_version, hdr.minor_runtime_version
        ),
    );
    if hdr.is_il_only() {
        crate::formats::common::put_u64(values, "pe.clr.is_il_only", 1);
    }
    if hdr.is_native_entrypoint() {
        crate::formats::common::put_u64(values, "pe.clr.is_native_entrypoint", 1);
    }
}

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
/// Classify the entry-point RVA against the section table and emit
/// overlay bounds (file bytes beyond the last on-disk section, with
/// the Certificate Table excluded so signed binaries don't look like
/// they all have giant overlays).
///
/// Emits to metrics:
/// - `pe.entry_in_header`     — EP RVA lands inside the SizeOfHeaders region.
/// - `pe.entry_in_writable_section` — EP's section has IMAGE_SCN_MEM_WRITE.
/// - `pe.entry_outside_sections`    — EP non-zero, not in any section,
///   and the file is an EXE (not a DLL/driver where EP=0 is normal).
/// - `pe.has_overlay`, `pe.overlay_offset`, `pe.overlay_size`,
///   `pe.overlay_end` — overlay extent in file-offset space.
///
/// Emits to values:
/// - `pe.entry_section` — name of the section containing the EP RVA.
fn entry_and_overlay(pe: &PE<'_>, bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    let Some(opt) = pe.header.optional_header.as_ref() else {
        return;
    };
    let ep_rva = u64::from(opt.standard_fields.address_of_entry_point);
    let size_of_headers = u64::from(opt.windows_fields.size_of_headers);

    if size_of_headers != 0 && ep_rva != 0 && ep_rva < size_of_headers {
        metrics.insert("pe.entry_in_header", 1.0);
    }

    let mut ep_in_section = false;
    for section in &pe.sections {
        let start = u64::from(section.virtual_address);
        let span = u64::from(section.virtual_size).max(u64::from(section.size_of_raw_data));
        let end = start.saturating_add(span);
        if ep_rva >= start && ep_rva < end {
            ep_in_section = true;
            // IMAGE_SCN_MEM_WRITE = 0x8000_0000.
            if section.characteristics & 0x8000_0000 != 0 {
                metrics.insert("pe.entry_in_writable_section", 1.0);
            }
            if let Ok(name) = section.name() {
                put_str(values, "pe.entry_section", name);
            }
            break;
        }
    }
    // EP=0 on a DLL or driver is normal; only flag "outside sections"
    // when the file is structurally an EXE with a non-zero EP.
    if !ep_in_section && ep_rva != 0 && !pe.is_lib {
        metrics.insert("pe.entry_outside_sections", 1.0);
    }

    // Overlay = file bytes past the last on-disk section extent, with
    // the Certificate Table (Authenticode blob) excluded — signed PEs
    // would otherwise always show a giant overlay.
    let sections_end: u64 = pe
        .sections
        .iter()
        .map(|s| u64::from(s.pointer_to_raw_data).saturating_add(u64::from(s.size_of_raw_data)))
        .max()
        .unwrap_or(0);
    let file_size = bytes.len() as u64;
    if sections_end == 0 || sections_end >= file_size {
        return;
    }
    let overlay_end = opt
        .data_directories
        .get_certificate_table()
        .map(|dir| u64::from(dir.virtual_address))
        .filter(|&cert_start| cert_start >= sections_end && cert_start < file_size)
        .unwrap_or(file_size);
    if overlay_end <= sections_end {
        return;
    }
    metrics.insert("pe.has_overlay", 1.0);
    metrics.insert("pe.overlay_offset", sections_end as f64);
    metrics.insert("pe.overlay_end", overlay_end as f64);
    metrics.insert("pe.overlay_size", (overlay_end - sections_end) as f64);
}

/// Header-arithmetic anomalies pefile flags as tampering signals.
/// Counts go on metrics; section name lists are emitted to values as
/// `pe.misaligned_sections[]` / `pe.overflowing_sections[]` /
/// `pe.overlapping_sections[]` so trait authors can match on names.
fn section_anomalies(pe: &PE<'_>, bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    let file_size = bytes.len() as u64;
    let file_alignment = pe
        .header
        .optional_header
        .as_ref()
        .map(|h| h.windows_fields.file_alignment)
        .unwrap_or(0);

    let mut overflow_names: Vec<String> = Vec::new();
    let mut misaligned_names: Vec<String> = Vec::new();
    let mut bss_like: u64 = 0;
    for section in &pe.sections {
        let name = section.name().unwrap_or("").to_string();
        let raw_end = u64::from(section.pointer_to_raw_data)
            .saturating_add(u64::from(section.size_of_raw_data));
        if section.size_of_raw_data > 0 && raw_end > file_size {
            overflow_names.push(name.clone());
        }
        if file_alignment > 0
            && section.pointer_to_raw_data != 0
            && section.pointer_to_raw_data % file_alignment != 0
        {
            misaligned_names.push(name.clone());
        }
        // BSS-like: raw size zero, virtual size non-zero, name not in
        // the standard set (`.bss`/`.tls`). Standard names on legitimate
        // Borland/Delphi binaries would otherwise produce noise.
        if section.size_of_raw_data == 0 && section.virtual_size != 0 {
            let lower = name.to_ascii_lowercase();
            if !matches!(lower.as_str(), ".bss" | "bss" | ".tls" | "tls") {
                bss_like += 1;
            }
        }
    }

    metrics.insert("pe.section_overflow_count", overflow_names.len() as f64);
    metrics.insert("pe.misaligned_section_count", misaligned_names.len() as f64);
    metrics.insert("pe.bss_like_section_count", bss_like as f64);
    if !overflow_names.is_empty() {
        values.insert(
            "pe.overflowing_sections",
            JsonValue::Array(overflow_names.into_iter().map(JsonValue::String).collect()),
        );
    }
    if !misaligned_names.is_empty() {
        values.insert(
            "pe.misaligned_sections",
            JsonValue::Array(
                misaligned_names
                    .into_iter()
                    .map(JsonValue::String)
                    .collect(),
            ),
        );
    }

    // Section overlap (virtual extent intersection). O(n log n) over
    // a section count capped at ~96 by the COFF format.
    if pe.sections.len() > 1 {
        let mut by_va: Vec<(u32, u32, String)> = pe
            .sections
            .iter()
            .map(|s| {
                let span = s.virtual_size.max(s.size_of_raw_data);
                let name = s.name().unwrap_or("").to_string();
                (
                    s.virtual_address,
                    s.virtual_address.saturating_add(span),
                    name,
                )
            })
            .collect();
        by_va.sort_by_key(|t| t.0);
        let mut overlap_names: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();
        for w in by_va.windows(2) {
            if w[0].1 > w[1].0 && w[1].0 >= w[0].0 {
                overlap_names.insert(w[0].2.clone());
                overlap_names.insert(w[1].2.clone());
            }
        }
        if !overlap_names.is_empty() {
            metrics.insert("pe.section_overlap_count", overlap_names.len() as f64);
            values.insert(
                "pe.overlapping_sections",
                JsonValue::Array(overlap_names.into_iter().map(JsonValue::String).collect()),
            );
        }
    }

    // Section count vs COFF header field — header tampering signal.
    if pe.header.coff_header.number_of_sections as usize != pe.sections.len() {
        metrics.insert("pe.section_count_mismatch", 1.0);
    }
}

/// Count exports whose first instruction shares a jump/call target
/// with another export — the canonical stub-thunk aliasing pattern
/// (malware aliasing N export names to a single payload via `JMP
/// fcn_X`). Decodes one instruction per export RVA via `iced_x86`,
/// groups by `near_branch_target`, and emits the population count of
/// every group with ≥2 members.
fn aliased_exports(pe: &PE<'_>, bytes: &[u8], metrics: &mut Metrics) {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic};
    use std::collections::HashMap;

    if pe.exports.is_empty() {
        return;
    }
    let Some(opt) = pe.header.optional_header.as_ref() else {
        return;
    };
    use goblin::pe::optional_header::{MAGIC_32, MAGIC_64};
    let bitness = match opt.standard_fields.magic {
        MAGIC_32 => 32u32,
        MAGIC_64 => 64u32,
        _ => return,
    };

    let mut targets: HashMap<u64, u32> = HashMap::new();
    for export in &pe.exports {
        let rva = export.rva;
        let Some(file_offset) = rva_to_file_offset(pe, rva as u32) else {
            continue;
        };
        if file_offset + 16 > bytes.len() {
            continue;
        }
        let code = &bytes[file_offset..file_offset + 16];
        let mut decoder = Decoder::with_ip(bitness, code, rva as u64, DecoderOptions::NONE);
        if let Some(instr) = decoder.iter().next() {
            let target = match instr.mnemonic() {
                Mnemonic::Jmp | Mnemonic::Call => {
                    let t = instr.near_branch_target();
                    if t != 0 {
                        t
                    } else {
                        rva as u64
                    }
                }
                _ => rva as u64,
            };
            *targets.entry(target).or_insert(0) += 1;
        }
    }
    let aliased: u32 = targets.values().filter(|&&c| c > 1).copied().sum();
    if aliased > 0 {
        metrics.insert("pe.aliased_export_count", f64::from(aliased));
    }
}

/// Map a PE RVA to its on-disk file offset by walking the section
/// table. Returns `None` for RVAs outside any section's virtual extent.
fn rva_to_file_offset(pe: &PE<'_>, rva: u32) -> Option<usize> {
    for section in &pe.sections {
        let start = section.virtual_address;
        let span = section.virtual_size.max(section.size_of_raw_data);
        if rva >= start && rva < start.saturating_add(span) {
            let delta = rva - start;
            return Some((section.pointer_to_raw_data + delta) as usize);
        }
    }
    None
}

/// PE optional-header checksum. The header carries a stored value; the
/// canonical algorithm computes a 16-bit summation over the whole file
/// with the checksum field itself zeroed. Genuine binaries from
/// Microsoft / signed third-party builds match; modified payloads
/// (post-pack patches, dropper-injected code) usually don't.
///
/// Emits:
/// - `pe.checksum`           — value stored in the header.
/// - `pe.computed_checksum`  — value the algorithm produces.
/// - `pe.checksum_valid`     — 1.0 iff the stored value is non-zero
///   and matches the computed one. Many legitimate builds emit a
///   zero checksum, so we only treat non-zero stored values as a
///   verification claim.
fn checksum(pe: &PE<'_>, bytes: &[u8], metrics: &mut Metrics) {
    let Some(opt) = pe.header.optional_header.as_ref() else {
        return;
    };
    let stored = opt.windows_fields.check_sum;
    metrics.insert("pe.checksum", f64::from(stored));

    use goblin::pe::optional_header::{
        MAGIC_32, MAGIC_64, OFFSET_WINDOWS_FIELDS_32_CHECKSUM, OFFSET_WINDOWS_FIELDS_64_CHECKSUM,
        SIZEOF_STANDARD_FIELDS_32, SIZEOF_STANDARD_FIELDS_64,
    };
    let pe_offset = pe.header.dos_header.pe_pointer as usize;
    let opt_header_offset = pe_offset + 4 + 20; // signature + COFF header
    let checksum_offset = match opt.standard_fields.magic {
        MAGIC_32 => {
            opt_header_offset + SIZEOF_STANDARD_FIELDS_32 + OFFSET_WINDOWS_FIELDS_32_CHECKSUM
        }
        MAGIC_64 => {
            opt_header_offset + SIZEOF_STANDARD_FIELDS_64 + OFFSET_WINDOWS_FIELDS_64_CHECKSUM
        }
        _ => return,
    };
    if checksum_offset + 4 > bytes.len() {
        return;
    }
    let computed = pe_checksum(bytes, checksum_offset);
    metrics.insert("pe.computed_checksum", f64::from(computed));
    if stored != 0 {
        metrics.insert("pe.checksum_valid", f64::from(u8::from(stored == computed)));
    }
}

/// Microsoft's documented PE checksum algorithm: 16-bit one's-complement
/// sum over the whole file (skipping the checksum field's own 4 bytes),
/// then add the file length. Same algorithm `imagehlp.dll` /
/// `editbin /release` use.
fn pe_checksum(data: &[u8], checksum_offset: usize) -> u32 {
    let mut sum: u64 = 0;
    let mut i = 0usize;
    while i + 1 < data.len() {
        if i == checksum_offset {
            i += 4;
            continue;
        }
        sum += u64::from(u16::from_le_bytes([data[i], data[i + 1]]));
        sum = (sum & 0xffff) + (sum >> 16);
        i += 2;
    }
    if i < data.len() {
        sum += u64::from(data[i]);
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = (sum & 0xffff) + (sum >> 16);
    sum += data.len() as u64;
    sum as u32
}

/// DOS stub anomalies — the bytes between the MZ header and the PE
/// signature. Linkers stamp the canonical "This program cannot be run
/// in DOS mode" banner here; absent / zeroed regions are minor evasion
/// or hand-rolled-builder tells.
fn dos_stub_anomalies(pe: &PE<'_>, bytes: &[u8], metrics: &mut Metrics) {
    let pe_offset = pe.header.dos_header.pe_pointer as usize;
    if pe_offset <= 0x40 || pe_offset > bytes.len() {
        return;
    }
    let stub = &bytes[0x40..pe_offset];
    let canonical = b"This program cannot be run in DOS mode";
    let has_banner = stub.windows(canonical.len()).any(|w| w == canonical);
    if !has_banner {
        metrics.insert("pe.dos_stub_modified", 1.0);
    }
    if stub.iter().all(|&b| b == 0) {
        metrics.insert("pe.dos_stub_zeroed", 1.0);
    }
}

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
    let dir = &lc.directory;
    let mut obj = serde_json::Map::new();
    // Raw numeric fields land under canonical names. Each is Option<u64>
    // in goblin — skip when None rather than emitting a zero, so trait
    // authors can use `exists:` to discriminate "PE has a Load Config
    // directory but no security_cookie field" from "field present and
    // zero" (the latter is its own tampering signal: cleared cookie).
    if let Some(v) = dir.security_cookie {
        obj.insert("security_cookie".into(), JsonValue::Number(v.into()));
    }
    if let Some(v) = dir.guard_cf_check_function_pointer {
        obj.insert(
            "guard_cf_check_function_pointer".into(),
            JsonValue::Number(v.into()),
        );
    }
    if let Some(v) = dir.guard_cf_function_table {
        obj.insert(
            "guard_cf_function_table".into(),
            JsonValue::Number(v.into()),
        );
    }
    if let Some(v) = dir.guard_cf_function_count {
        obj.insert(
            "guard_cf_function_count".into(),
            JsonValue::Number(v.into()),
        );
    }
    if let Some(flags) = dir.guard_flags {
        // Both forms: raw u32 (for round-trip parity with goblin's
        // typed bitmask) and a string-flag array (for human-readable
        // trait matches against `cf_instrumented` / `cfw_instrumented`).
        obj.insert("guard_flags_raw".into(), JsonValue::Number(flags.into()));
        let names = guard_flag_names(flags);
        if !names.is_empty() {
            obj.insert(
                "guard_flags".into(),
                JsonValue::Array(
                    names
                        .into_iter()
                        .map(|s| JsonValue::String(s.to_string()))
                        .collect(),
                ),
            );
        }
    }
    if !obj.is_empty() {
        values.insert("pe.load_config", JsonValue::Object(obj));
    }
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
        let mut functions = crate::Functions::new();
        let mut errors = Errors::new();
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

    /// A normal local-export fixture has no forwarded exports —
    /// every `Export.forward_to` is `None` and the
    /// `pe.forwarded_export_count` metric is absent.
    #[test]
    fn normal_exports_emit_no_forward_to() {
        let bytes = read_fixture("test.exe");
        let mut v = Values::new();
        let mut s = Strings::default();
        let mut m = Metrics::new();
        let mut sections = Vec::new();
        let mut imports = crate::Imports::new();
        let mut exports = crate::Exports::new();
        let mut functions = crate::Functions::new();
        let mut errors = Errors::new();
        extract(
            &bytes,
            &mut v,
            &mut s,
            &mut m,
            &mut sections,
            &mut imports,
            &mut exports,
            &mut functions,
            &mut errors,
        )
        .unwrap();
        for exp in exports.iter() {
            assert!(
                exp.forward_to.is_none(),
                "test.exe shouldn't have forwarded exports; got {:?}",
                exp.forward_to,
            );
        }
        assert!(m.get("pe.forwarded_export_count").is_none());
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
        let mut functions = crate::Functions::new();
        let mut errors = Errors::new();
        extract(
            &bytes,
            &mut v,
            &mut s,
            &mut m,
            &mut sections,
            &mut imports,
            &mut exports,
            &mut functions,
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

    /// A clean MSVC-produced PE keeps the canonical "This program
    /// cannot be run in DOS mode" banner and a non-zero stub. The
    /// emitter must NOT raise either anomaly flag.
    #[test]
    fn dos_stub_anomalies_silent_on_clean_pe() {
        let bytes = read_fixture("test.exe");
        let (_, _, m) = run(&bytes);
        assert!(
            m.get("pe.dos_stub_modified").is_none(),
            "clean PE should not flag dos_stub_modified",
        );
        assert!(
            m.get("pe.dos_stub_zeroed").is_none(),
            "clean PE should not flag dos_stub_zeroed",
        );
    }

    /// Rewrite the DOS stub region of a real PE with zeros and verify
    /// the emitter raises both anomaly bits. The PE remains parseable
    /// because we only touch bytes 0x40..pe_offset.
    #[test]
    fn dos_stub_anomalies_fires_on_zeroed_stub() {
        let mut bytes = read_fixture("test.exe");
        // e_lfanew lives at 0x3C..0x40 as a little-endian u32 — locates
        // the PE header start, which is the upper bound of the stub
        // region the anomaly detector inspects.
        let pe_offset =
            u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
        assert!(pe_offset > 0x40, "fixture should have a stub region");
        for b in bytes[0x40..pe_offset].iter_mut() {
            *b = 0;
        }
        let (_, _, m) = run(&bytes);
        assert!(
            m.get("pe.dos_stub_modified").is_some(),
            "zeroed stub should flag dos_stub_modified",
        );
        assert!(
            m.get("pe.dos_stub_zeroed").is_some(),
            "zeroed stub should flag dos_stub_zeroed",
        );
    }

    /// Overwrite the canonical banner with garbage but keep the stub
    /// non-zero — `dos_stub_modified` should fire, `dos_stub_zeroed`
    /// must not.
    #[test]
    fn dos_stub_modified_without_zeroed() {
        let mut bytes = read_fixture("test.exe");
        let pe_offset =
            u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
        for b in bytes[0x40..pe_offset].iter_mut() {
            *b = 0xab;
        }
        let (_, _, m) = run(&bytes);
        assert!(
            m.get("pe.dos_stub_modified").is_some(),
            "missing canonical banner should flag dos_stub_modified",
        );
        assert!(
            m.get("pe.dos_stub_zeroed").is_none(),
            "non-zero garbage stub must NOT be flagged as zeroed",
        );
    }

    /// `pe.rich.entries` is the flat-path under which the Rich Header
    /// emitter writes the decoded CompID tuples. The fixture is an
    /// MSVC-linked PE so it carries a Rich header; the array must be
    /// present and non-empty.
    #[test]
    fn rich_entries_populated_on_msvc_pe() {
        let bytes = read_fixture("test.exe");
        let (v, _, _) = run(&bytes);
        let entries = v
            .get("pe.rich.entries")
            .and_then(|x| x.as_array())
            .expect("MSVC-built fixture should carry pe.rich.entries");
        assert!(!entries.is_empty(), "rich entries should be non-empty");
        // `pe.rich.hash` and `pe.rich.key` must also be present whenever
        // entries are emitted — they're written in the same code path.
        assert!(v.get("pe.rich.hash").is_some());
        assert!(v.get("pe.rich.key").is_some());
    }
}
