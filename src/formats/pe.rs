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
//! `pe.optional.subsystem`. Symbol tables live in the typed imports /
//! exports views rather than being mirrored into `values`.

use goblin::pe::{PE, header::CoffHeader, optional_header::OptionalHeader};
use serde_json::Value as JsonValue;

use crate::error::Error;
use crate::formats::common::{
    XorScan, extract_binary_strings, extract_binary_strings_from_object, hex_encode, put_i64,
    put_str, put_u64, rizin_decision, rizin_fallback_with_sections,
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
    symbols_out: &mut crate::Symbols,
    errors_out: &mut Errors,
) -> Result<(), Error> {
    // All strings — ASCII, section names, and UTF-16 (resource / version-info)
    // runs — come from the single stng pass below: it scans the whole buffer
    // for wide strings at absolute file offsets, including the unparseable
    // case (it recognises the `MZ` header itself). ELF and Mach-O rely on the
    // same pass, so there's no separate raw UTF-16 scan here.

    // goblin treats a Rich header carrying the `Rich` marker but no
    // decodable `DanS` table as a fatal parse error — strict, permissive,
    // and the header-only fallback all abort, leaving zero sections and
    // imports. Packers and mangled samples emit that shape routinely.
    // Neutralize it on a copy so structural recovery proceeds; raw byte
    // readers (section data, overlay, authenticode, our own pe_rich
    // extractor) keep reading the untouched `bytes`.
    let rich_sanitized = goblin_safe::neutralize_malformed_rich_header(bytes);
    let pe_bytes: &[u8] = rich_sanitized.as_deref().unwrap_or(bytes);

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
    let parse_outcome = goblin_safe::parse_pe(pe_bytes);
    // Record the failure mode (if any) into the structured errors
    // view *before* we attempt the header-only fallback, so consumers
    // can see exactly which sub-stage tripped even when the fallback
    // succeeds.
    match &parse_outcome {
        goblin_safe::GoblinOutcome::Failed(e) => {
            errors_out.record_malformed(crate::Stage::PeParse, e.to_string());
            metrics.insert("pe.parse_failed", 1.0);
        }
        goblin_safe::GoblinOutcome::Panicked(msg) => {
            errors_out.record_panic(crate::Stage::PeParse, msg);
            metrics.insert("pe.parse_panicked", 1.0);
        }
        goblin_safe::GoblinOutcome::Ok(_) => {}
    }
    if let Some(pe) = parse_outcome.ok() {
        // Reuse this parse for string extraction (move into an Object for stng,
        // then move back out) so the binary isn't parsed a second time.
        let object = goblin::Object::PE(pe);
        extract_binary_strings_from_object(&object, bytes, strings, XorScan::Yes);
        let goblin::Object::PE(pe) = object else {
            unreachable!("constructed as Object::PE")
        };
        coff_header(&pe.header.coff_header, values);
        dos_header(&pe.header, values);
        if let Some(ref opt) = pe.header.optional_header {
            optional_header(opt, values);
            binary_flags(opt, metrics);
        }
        sections(&pe, bytes, metrics, sections_out);
        imports(&pe, values, metrics, symbols_out);
        native_resolver_signals(&pe, bytes, values, metrics);
        exports(&pe, values, metrics, symbols_out);
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
                // Resource-directory TimeDateStamp, set by the resource
                // compiler at link time. Often stable across rebuilds, so a
                // change between releases of an otherwise-stable binary is a
                // tampering signal.
                let ts = rd.image_resource_directory.time_date_stamp;
                if ts != 0 {
                    put_u64(values, "pe.resource_timestamp", u64::from(ts));
                }
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
                    super::pe_version_info::extract(vi, bytes, values, metrics);
                }
                if let Some(ref md) = rd.manifest_data {
                    super::pe_manifest::extract(md.data, values);
                }
            });
            if let goblin_safe::GoblinOutcome::Panicked(msg) = walk {
                errors_out.record_panic(crate::Stage::PeResourceWalk, msg);
                metrics.insert("pe.resource_walk_panicked", 1.0);
            }
        }
        if let Some(ref dbg) = pe.debug_data {
            super::pe_debug::extract(dbg, values);
        }
        bound_imports(&pe, bytes, values, metrics);
        delay_imports(&pe, bytes, values, metrics, symbols_out);
        base_relocations(&pe, bytes, values, metrics);
        tls_callbacks(&pe, values, metrics);
        inflated_sections(&pe, values);
        load_config(&pe, bytes, values, metrics);
        entry_and_overlay(&pe, bytes, values, metrics);
        section_anomalies(&pe, bytes, values, metrics);
        dos_stub_anomalies(&pe, bytes, metrics);
        checksum(&pe, bytes, metrics);
        aliased_exports(&pe, bytes, metrics);
        clr_metadata(&pe, bytes, values, metrics);
        clr_resources(&pe, bytes, metrics);
        data_directories(&pe, values);
        data_directory_anomalies(&pe, bytes, values, metrics);
        super::pe_image_hash::extract(&pe, bytes, values, metrics);
        super::pe_rich::extract(bytes, values);
        super::upx::detect(bytes, values);
        let go_sections = super::go_buildinfo::GoSections {
            buildid_note: None,
            pclntab: pe_section_bytes(&pe, bytes, ".gopclntab"),
            rodata: pe_section_bytes(&pe, bytes, ".rdata"),
        };
        let has_go_pclntab = go_sections
            .pclntab
            .is_some_and(super::go_buildinfo::has_pclntab_magic);
        super::go_buildinfo::detect(bytes, values, "pe", None, &go_sections);
        super::build_toolchain::from_pe_rich(values);
        // Importless PEs are the narrow parsed-PE class where function
        // recovery can correlate API-hash callsites. It shares the same
        // cross-platform admission facts, including the Go exclusion.
        rizin_importless_analysis(
            &pe,
            bytes,
            values,
            strings,
            sections_out,
            symbols_out,
            metrics,
            has_go_pclntab,
        );
        rizin_fallback_with_sections(
            bytes,
            strings,
            symbols_out,
            sections_out,
            metrics,
            "pe",
            has_go_pclntab,
        );
        return Ok(());
    }

    // Full parse failed: recover strings via stng's own byte-level scan
    // (it parses the bytes itself, tolerating the malformed structure).
    extract_binary_strings(bytes, strings, XorScan::Yes);

    // Header-only fallback. The header parse is far more tolerant —
    // we can still surface machine / subsystem / characteristics +
    // Authenticode for binaries whose import directory is malformed
    // or stripped (packed installers, Go binaries, obfuscated builds).
    let header = goblin::pe::header::Header::parse(pe_bytes)
        .map_err(|e| Error::malformed("pe", e.to_string()))?;
    coff_header(&header.coff_header, values);
    dos_header(&header, values);
    if let Some(ref opt) = header.optional_header {
        optional_header(opt, values);
        binary_flags(opt, metrics);
    }
    authenticode_from_header(&header, bytes, values, metrics);
    // Header-only fallback ran. Record that as a structured
    // fallback entry alongside the legacy `pe.partial_parse` bool
    // so trait authors can branch on either path. The bool is
    // retained as the canonical "is this a partial parse?" key for
    // existing rules.
    values.insert("pe.partial_parse", serde_json::Value::Bool(true));
    errors_out.record_fallback(crate::Stage::PeParse, "header-only fallback");
    metrics.insert("pe.partial_parse", 1.0);
    // goblin couldn't parse the section table / import directory at all
    // (the header-only path leaves `sections_out` and `symbols_out` empty).
    // This is exactly the case rizin recovery exists for — without it,
    // malformed/packed PEs that rizin parses fine surface zero sections and
    // zero imports, breaking every section-scoped trait. The success branch
    // already calls this; the header-only branch must too. The helper no-ops
    // when goblin did supply something, so it's safe to call unconditionally.
    rizin_fallback_with_sections(
        bytes,
        strings,
        symbols_out,
        sections_out,
        metrics,
        "pe",
        false,
    );
    Ok(())
}

/// Cheap native-code indicators for manual Windows API resolution.
///
/// These are deliberately mechanics, not a claim that a binary communicates
/// over the network. Combined, they distinguish an importless PE's custom
/// module/export resolver from an ordinary PEB read or arithmetic loop.
fn native_resolver_signals(pe: &PE<'_>, bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    // Limit native signatures to executable sections. Scanning resources and
    // encrypted data would make an instruction-shaped byte sequence a noisy
    // fact rather than evidence of executable resolver code.
    let mut peb_x86 = 0;
    let mut peb_x64 = 0;
    let mut export_walks = 0;
    let mut hash_loops = 0;
    let mut peb_sites = Vec::new();
    let mut export_walk_sites = Vec::new();
    let mut hash_profiles = Vec::new();
    for section in pe
        .sections
        .iter()
        .filter(|section| section.characteristics & 0x2000_0000 != 0)
    {
        let start = section.pointer_to_raw_data as usize;
        let end = start.saturating_add(section.size_of_raw_data as usize);
        let Some(code) = bytes.get(start..end) else {
            continue;
        };
        for local_offset in find_bytes(code, b"\x64\xa1\x30\x00\x00\x00") {
            peb_x86 += 1;
            peb_sites.push(native_site(
                pe,
                section,
                start.saturating_add(local_offset),
                serde_json::json!({
                    "architecture": "x86",
                    "mechanism": "fs:[0x30]",
                }),
            ));
        }
        for local_offset in find_bytes(code, b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00") {
            peb_x64 += 1;
            peb_sites.push(native_site(
                pe,
                section,
                start.saturating_add(local_offset),
                serde_json::json!({
                    "architecture": "x86_64",
                    "mechanism": "gs:[0x60]",
                }),
            ));
        }
        for walk in find_checked_export_walks_x86(code) {
            export_walks += 1;
            let mut fact = native_site(
                pe,
                section,
                start.saturating_add(walk.mz_check),
                serde_json::json!({
                    "architecture": "x86",
                    "kind": "checked_pe32_export_directory_walk",
                    "checks": ["mz_signature", "pe_signature", "export_rva", "export_size"],
                }),
            );
            if let Some(object) = fact.as_object_mut() {
                object.insert(
                    "anchors".to_string(),
                    serde_json::json!({
                        "mz_check_file_offset": start.saturating_add(walk.mz_check),
                        "e_lfanew_file_offset": start.saturating_add(walk.e_lfanew),
                        "pe_check_file_offset": start.saturating_add(walk.pe_check),
                        "export_rva_file_offset": start.saturating_add(walk.export_rva),
                        "export_size_file_offset": start.saturating_add(walk.export_size),
                    }),
                );
            }
            export_walk_sites.push(fact);
        }
        for profile in find_custom_byte_hash_profiles_x86(code) {
            hash_loops += 1;
            let mut fact = native_site(
                pe,
                section,
                start.saturating_add(profile.loop_offset),
                serde_json::json!({
                    "architecture": "x86",
                    "kind": profile.kind,
                    "multiplier": profile.multiplier,
                    "xor_constant": profile.xor_constant,
                    "rotate": {
                        "direction": "left",
                        "bits": profile.rotate_bits,
                    },
                }),
            );
            if let Some(object) = fact.as_object_mut() {
                if let Some(seed) = profile.seed {
                    object.insert("seed".to_string(), serde_json::json!(seed));
                }
                if profile.ascii_lowercase {
                    object.insert(
                        "normalization".to_string(),
                        JsonValue::String("ascii_lowercase".to_string()),
                    );
                }
            }
            hash_profiles.push(fact);
        }
    }
    if peb_x86 > 0 {
        metrics.insert("pe.peb_access_x86_count", peb_x86 as f64);
    }
    if peb_x64 > 0 {
        metrics.insert("pe.peb_access_x64_count", peb_x64 as f64);
    }
    if export_walks > 0 {
        metrics.insert("pe.checked_export_walk_x86_count", export_walks as f64);
    }
    if hash_loops > 0 {
        metrics.insert("pe.custom_byte_hash_loop_x86_count", hash_loops as f64);
    }
    if !peb_sites.is_empty() {
        values.insert("pe.peb_access_sites", JsonValue::Array(peb_sites));
    }
    if !export_walk_sites.is_empty() {
        values.insert(
            "pe.checked_export_walk_sites",
            JsonValue::Array(export_walk_sites),
        );
    }
    if !hash_profiles.is_empty() {
        values.insert("pe.api_hash_profiles", JsonValue::Array(hash_profiles));
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    haystack
        .windows(needle.len())
        .enumerate()
        .filter_map(|(offset, window)| (window == needle).then_some(offset))
        .collect()
}

fn native_site(
    pe: &PE<'_>,
    section: &goblin::pe::section_table::SectionTable,
    file_offset: usize,
    mut fact: JsonValue,
) -> JsonValue {
    let section_file_offset = section.pointer_to_raw_data as usize;
    let delta = file_offset.saturating_sub(section_file_offset);
    let rva = u64::from(section.virtual_address).saturating_add(delta as u64);
    let va = pe.image_base.saturating_add(rva);
    if let Some(object) = fact.as_object_mut() {
        object.insert("file_offset".to_string(), serde_json::json!(file_offset));
        object.insert("rva".to_string(), serde_json::json!(rva));
        object.insert("va".to_string(), serde_json::json!(va));
        object.insert(
            "section".to_string(),
            JsonValue::String(section.name().unwrap_or("").to_string()),
        );
    }
    fact
}

/// Recover function facts and correlate manual export walkers with their
/// concrete callsites for small importless PEs. This turns "there is an API
/// hash loop somewhere" into the more useful fact "this call requested this
/// hash, which exactly matches this known API under the recovered profile".
fn rizin_importless_analysis(
    pe: &PE<'_>,
    bytes: &[u8],
    values: &mut Values,
    strings: &Strings,
    sections: &[Section],
    symbols: &mut crate::Symbols,
    metrics: &mut Metrics,
    go_pclntab: bool,
) {
    const MAX_IMPORTLESS_ANALYSIS_BYTES: usize = 5 * 1024 * 1024;
    if bytes.len() > MAX_IMPORTLESS_ANALYSIS_BYTES
        || symbols
            .iter()
            .any(|symbol| symbol.kind() == crate::SymbolKind::Import)
    {
        return;
    }
    if !rizin_decision(
        crate::formats::common::NativeFormat::Pe,
        bytes,
        strings,
        sections,
        symbols,
        metrics,
        go_pclntab,
    )
    .runs()
    {
        return;
    }
    let Some(recovery) = crate::rizin::recover(bytes) else {
        return;
    };
    recover_api_hash_requests(pe, bytes, values, metrics, &recovery);
    let counts = recovery.apply(symbols, metrics);
    metrics.insert("pe.rizin_importless_analysis", 1.0);
    if counts.functions > 0 {
        metrics.insert(
            "pe.rizin_importless_function_count",
            f64::from(counts.functions),
        );
    }
}

#[derive(Debug, Clone)]
struct LocatedHashProfile {
    va: u64,
    kind: String,
    seed: u32,
    multiplier: u32,
    xor_constant: u32,
    rotate_bits: u32,
    ascii_lowercase: bool,
}

fn recover_api_hash_requests(
    pe: &PE<'_>,
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    recovery: &crate::rizin::RizinRecovery,
) {
    let walk_sites: Vec<u64> = values
        .get("pe.checked_export_walk_sites")
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(|site| site.get("va").and_then(JsonValue::as_u64))
        .collect();
    if walk_sites.is_empty() {
        return;
    }
    let ranges = recovery.function_ranges();
    let resolver_targets: Vec<u64> = ranges
        .iter()
        .filter(|(start, size)| {
            walk_sites
                .iter()
                .any(|site| va_in_function(*site, *start, *size))
        })
        .map(|(start, _)| *start)
        .collect();
    if resolver_targets.is_empty() {
        return;
    }

    let profiles = located_hash_profiles(values);
    let call_edges = recovery.direct_call_edges();
    let mut requests = Vec::new();
    let mut name_matches = 0_u32;
    let mut folded = 0_u32;
    for (caller_va, callsite_va, resolver_va) in &call_edges {
        if !resolver_targets.contains(resolver_va) {
            continue;
        }
        let resolver_range = ranges.iter().find(|(start, _)| start == resolver_va);
        let profile = resolver_range
            .and_then(|(start, size)| {
                profiles
                    .iter()
                    .find(|profile| va_in_function(profile.va, *start, *size))
            })
            .or_else(|| {
                call_edges
                    .iter()
                    .filter(|(caller, _, _)| caller == resolver_va)
                    .find_map(|(_, _, target)| {
                        let (start, size) = ranges.iter().find(|(start, _)| start == target)?;
                        profiles
                            .iter()
                            .find(|profile| va_in_function(profile.va, *start, *size))
                    })
            });
        let Some(profile) = profile else {
            continue;
        };
        let request = recover_x86_hash_argument(pe, bytes, *callsite_va);
        let mut fact = serde_json::json!({
            "kind": "hashed_pe_export_resolution",
            "architecture": "x86",
            "caller_va": caller_va,
            "callsite_va": callsite_va,
            "resolver_va": resolver_va,
            "hash_profile_kind": profile.kind,
            "hash_profile_va": profile.va,
        });
        if let Some(callsite_file_offset) = va_to_file_offset(pe, *callsite_va) {
            fact["callsite_file_offset"] = serde_json::json!(callsite_file_offset);
        }
        match request {
            Some((hash, source)) => {
                fact["hash"] = serde_json::json!(hash);
                fact["hash_hex"] = JsonValue::String(format!("0x{hash:08x}"));
                fact["hash_source"] = JsonValue::String(source.to_string());
                if source == "constant_folded_memory_xor_add" {
                    folded = folded.saturating_add(1);
                }
                let matches: Vec<_> = WINDOWS_API_HASH_CANDIDATES
                    .iter()
                    .filter(|candidate| hash_windows_name(profile, candidate.name) == hash)
                    .collect();
                if matches.len() == 1 {
                    let candidate = matches[0];
                    fact["resolved_name"] = JsonValue::String(candidate.name.to_string());
                    fact["resolved_library"] = JsonValue::String(candidate.library.to_string());
                    fact["resolution"] = JsonValue::String("exact_hash_match".to_string());
                    name_matches = name_matches.saturating_add(1);
                }
            }
            None => {
                fact["hash_source"] = JsonValue::String("runtime_expression".to_string());
            }
        }
        requests.push(fact);
    }
    if requests.is_empty() {
        return;
    }
    metrics.insert("pe.api_hash_resolver_request_count", requests.len() as f64);
    if folded > 0 {
        metrics.insert(
            "pe.api_hash_constant_folded_request_count",
            f64::from(folded),
        );
    }
    if name_matches > 0 {
        metrics.insert("pe.api_hash_name_match_count", f64::from(name_matches));
    }
    values.insert("pe.api_hash_resolver_requests", JsonValue::Array(requests));
}

fn va_in_function(va: u64, start: u64, size: u64) -> bool {
    va >= start && (size == 0 && va == start || size > 0 && va < start.saturating_add(size))
}

fn located_hash_profiles(values: &Values) -> Vec<LocatedHashProfile> {
    values
        .get("pe.api_hash_profiles")
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(|profile| {
            Some(LocatedHashProfile {
                va: profile.get("va")?.as_u64()?,
                kind: profile.get("kind")?.as_str()?.to_string(),
                seed: u32::try_from(profile.get("seed")?.as_u64()?).ok()?,
                multiplier: u32::try_from(profile.get("multiplier")?.as_u64()?).ok()?,
                xor_constant: u32::try_from(profile.get("xor_constant")?.as_u64()?).ok()?,
                rotate_bits: u32::try_from(profile.get("rotate")?.get("bits")?.as_u64()?).ok()?,
                ascii_lowercase: profile.get("normalization").and_then(JsonValue::as_str)
                    == Some("ascii_lowercase"),
            })
        })
        .collect()
}

fn hash_windows_name(profile: &LocatedHashProfile, name: &str) -> u32 {
    let mut hash = profile.seed;
    for mut byte in name.bytes() {
        if profile.ascii_lowercase && byte.is_ascii_uppercase() {
            byte = byte.to_ascii_lowercase();
        }
        hash = match profile.kind.as_str() {
            "multiply_xor_rotate" => {
                (hash.wrapping_mul(profile.multiplier) ^ u32::from(byte) ^ profile.xor_constant)
                    .rotate_left(profile.rotate_bits)
            }
            "xor_rotate_multiply_xor" => {
                (hash ^ profile.xor_constant)
                    .rotate_left(profile.rotate_bits)
                    .wrapping_mul(profile.multiplier)
                    ^ u32::from(byte)
            }
            _ => return 0,
        };
    }
    hash
}

fn recover_x86_hash_argument(
    pe: &PE<'_>,
    bytes: &[u8],
    callsite_va: u64,
) -> Option<(u32, &'static str)> {
    let callsite = va_to_file_offset(pe, callsite_va)?;
    let start = callsite.saturating_sub(48);
    let prefix = bytes.get(start..callsite)?;

    // cdecl/stdcall two-argument call: `push hash_imm32; push module; call`.
    if prefix.len() >= 6
        && prefix[prefix.len() - 6] == 0x68
        && (0x50..=0x57).contains(&prefix[prefix.len() - 1])
    {
        let push = &prefix[prefix.len() - 6..prefix.len() - 1];
        return Some((u32::from_le_bytes(push[1..5].try_into().ok()?), "immediate"));
    }

    // Common opaque-constant form:
    // mov eax,[absolute]; mov ecx,imm32; xor eax,ecx; add eax,imm32;
    // push eax; push module; call resolver.
    for expression in prefix.windows(19) {
        if expression[0] != 0xa1
            || expression[5] != 0xb9
            || !matches!(expression[10..12], [0x31, 0xc8] | [0x33, 0xc1])
            || expression[12] != 0x05
            || expression[17] != 0x50
        {
            continue;
        }
        let address = u64::from(u32::from_le_bytes(expression[1..5].try_into().ok()?));
        let memory_offset = va_to_file_offset(pe, address)?;
        let initial = u32::from_le_bytes(
            bytes
                .get(memory_offset..memory_offset.checked_add(4)?)?
                .try_into()
                .ok()?,
        );
        let xor = u32::from_le_bytes(expression[6..10].try_into().ok()?);
        let add = u32::from_le_bytes(expression[13..17].try_into().ok()?);
        return Some((
            (initial ^ xor).wrapping_add(add),
            "constant_folded_memory_xor_add",
        ));
    }
    None
}

fn va_to_file_offset(pe: &PE<'_>, va: u64) -> Option<usize> {
    let rva = va.checked_sub(pe.image_base)?;
    pe.sections.iter().find_map(|section| {
        let start = u64::from(section.virtual_address);
        let size = u64::from(section.size_of_raw_data);
        if rva < start || rva >= start.saturating_add(size) {
            return None;
        }
        usize::try_from(
            u64::from(section.pointer_to_raw_data).saturating_add(rva.saturating_sub(start)),
        )
        .ok()
    })
}

struct WindowsApiHashCandidate {
    library: &'static str,
    name: &'static str,
}

const WINDOWS_API_HASH_CANDIDATES: &[WindowsApiHashCandidate] = &[
    WindowsApiHashCandidate {
        library: "ntdll.dll",
        name: "NtAllocateVirtualMemory",
    },
    WindowsApiHashCandidate {
        library: "ntdll.dll",
        name: "NtClose",
    },
    WindowsApiHashCandidate {
        library: "ntdll.dll",
        name: "NtCreateFile",
    },
    WindowsApiHashCandidate {
        library: "ntdll.dll",
        name: "NtCreateProcess",
    },
    WindowsApiHashCandidate {
        library: "ntdll.dll",
        name: "NtCreateSection",
    },
    WindowsApiHashCandidate {
        library: "ntdll.dll",
        name: "NtCreateThreadEx",
    },
    WindowsApiHashCandidate {
        library: "ntdll.dll",
        name: "NtDelayExecution",
    },
    WindowsApiHashCandidate {
        library: "ntdll.dll",
        name: "NtFreeVirtualMemory",
    },
    WindowsApiHashCandidate {
        library: "ntdll.dll",
        name: "NtMapViewOfSection",
    },
    WindowsApiHashCandidate {
        library: "ntdll.dll",
        name: "NtOpenProcess",
    },
    WindowsApiHashCandidate {
        library: "ntdll.dll",
        name: "NtProtectVirtualMemory",
    },
    WindowsApiHashCandidate {
        library: "ntdll.dll",
        name: "NtQueryInformationProcess",
    },
    WindowsApiHashCandidate {
        library: "ntdll.dll",
        name: "NtQuerySystemInformation",
    },
    WindowsApiHashCandidate {
        library: "ntdll.dll",
        name: "NtReadVirtualMemory",
    },
    WindowsApiHashCandidate {
        library: "ntdll.dll",
        name: "NtResumeThread",
    },
    WindowsApiHashCandidate {
        library: "ntdll.dll",
        name: "NtSetInformationThread",
    },
    WindowsApiHashCandidate {
        library: "ntdll.dll",
        name: "NtTerminateProcess",
    },
    WindowsApiHashCandidate {
        library: "ntdll.dll",
        name: "NtUnmapViewOfSection",
    },
    WindowsApiHashCandidate {
        library: "ntdll.dll",
        name: "NtWaitForSingleObject",
    },
    WindowsApiHashCandidate {
        library: "ntdll.dll",
        name: "NtWriteVirtualMemory",
    },
    WindowsApiHashCandidate {
        library: "ntdll.dll",
        name: "RtlAllocateHeap",
    },
    WindowsApiHashCandidate {
        library: "ntdll.dll",
        name: "RtlCreateProcessParametersEx",
    },
    WindowsApiHashCandidate {
        library: "ntdll.dll",
        name: "RtlGetVersion",
    },
    WindowsApiHashCandidate {
        library: "ntdll.dll",
        name: "RtlInitUnicodeString",
    },
    WindowsApiHashCandidate {
        library: "kernel32.dll",
        name: "CreateProcessW",
    },
    WindowsApiHashCandidate {
        library: "kernel32.dll",
        name: "GetProcAddress",
    },
    WindowsApiHashCandidate {
        library: "kernel32.dll",
        name: "LoadLibraryA",
    },
    WindowsApiHashCandidate {
        library: "kernel32.dll",
        name: "VirtualAlloc",
    },
    WindowsApiHashCandidate {
        library: "kernel32.dll",
        name: "VirtualProtect",
    },
    WindowsApiHashCandidate {
        library: "winhttp.dll",
        name: "WinHttpConnect",
    },
    WindowsApiHashCandidate {
        library: "winhttp.dll",
        name: "WinHttpOpen",
    },
    WindowsApiHashCandidate {
        library: "winhttp.dll",
        name: "WinHttpOpenRequest",
    },
    WindowsApiHashCandidate {
        library: "winhttp.dll",
        name: "WinHttpReadData",
    },
    WindowsApiHashCandidate {
        library: "winhttp.dll",
        name: "WinHttpReceiveResponse",
    },
    WindowsApiHashCandidate {
        library: "winhttp.dll",
        name: "WinHttpSendRequest",
    },
    WindowsApiHashCandidate {
        library: "wininet.dll",
        name: "HttpOpenRequestA",
    },
    WindowsApiHashCandidate {
        library: "wininet.dll",
        name: "HttpSendRequestA",
    },
    WindowsApiHashCandidate {
        library: "wininet.dll",
        name: "InternetConnectA",
    },
    WindowsApiHashCandidate {
        library: "wininet.dll",
        name: "InternetOpenA",
    },
    WindowsApiHashCandidate {
        library: "wininet.dll",
        name: "InternetReadFile",
    },
    WindowsApiHashCandidate {
        library: "ws2_32.dll",
        name: "WSAStartup",
    },
    WindowsApiHashCandidate {
        library: "ws2_32.dll",
        name: "connect",
    },
    WindowsApiHashCandidate {
        library: "ws2_32.dll",
        name: "recv",
    },
    WindowsApiHashCandidate {
        library: "ws2_32.dll",
        name: "send",
    },
    WindowsApiHashCandidate {
        library: "ws2_32.dll",
        name: "socket",
    },
];

fn contains_after(
    bytes: &[u8],
    start: usize,
    max: usize,
    predicate: impl Fn(&[u8]) -> bool,
) -> Option<usize> {
    let end = start.saturating_add(max).min(bytes.len());
    (start..end).find(|&i| predicate(&bytes[i..]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CheckedExportWalk {
    mz_check: usize,
    e_lfanew: usize,
    pe_check: usize,
    export_rva: usize,
    export_size: usize,
}

fn find_checked_export_walks_x86(bytes: &[u8]) -> Vec<CheckedExportWalk> {
    bytes
        .windows(5)
        .enumerate()
        .filter(|(_, w)| {
            // `cmp word ptr [reg], 0x5a4d`: opcode 81 /7 with a memory
            // operand, not an arbitrary 81 instruction containing `MZ`.
            w[0] == 0x66
                && w[1] == 0x81
                && w[2] & 0x38 == 0x38
                && w[2] & 0xc0 != 0xc0
                && w[3..] == [0x4d, 0x5a]
        })
        .filter_map(|(start, _)| {
            let pe_offset = contains_after(bytes, start + 5, 64, |b| {
                // `mov reg, [reg+0x3c]` (the PE e_lfanew field).
                b.len() >= 3 && b[0] == 0x8b && b[1] & 0xc0 == 0x40 && b[2] == 0x3c
            })?;
            let signature = contains_after(bytes, pe_offset + 3, 64, |b| {
                // `cmp dword ptr [base+e_lfanew], 0x4550`.
                b.len() >= 7
                    && b[0] == 0x81
                    && b[1] & 0x38 == 0x38
                    && b[1] & 0xc0 != 0xc0
                    && b[3..7] == [0x50, 0x45, 0, 0]
            })?;
            let export_directory = contains_after(bytes, signature + 7, 64, |b| {
                // `mov reg, [base+e_lfanew+0x78]`: PE32 export directory.
                b.len() >= 4 && b[0] == 0x8b && b[1] & 0xc0 == 0x40 && b[3] == 0x78
            })?;
            let export_size = contains_after(bytes, export_directory + 4, 32, |b| {
                // A checked resolver also reads the paired export-directory
                // size field at +0x7c before dereferencing the directory.
                b.len() >= 4 && b[0] == 0x8b && b[1] & 0xc0 == 0x40 && b[3] == 0x7c
            })?;
            Some(CheckedExportWalk {
                mz_check: start,
                e_lfanew: pe_offset,
                pe_check: signature,
                export_rva: export_directory,
                export_size,
            })
        })
        .collect()
}

#[cfg(test)]
fn count_checked_export_walks_x86(bytes: &[u8]) -> usize {
    find_checked_export_walks_x86(bytes).len()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ApiHashProfile {
    loop_offset: usize,
    kind: &'static str,
    seed: Option<u32>,
    multiplier: u32,
    xor_constant: u32,
    rotate_bits: u8,
    ascii_lowercase: bool,
}

fn find_custom_byte_hash_profiles_x86(bytes: &[u8]) -> Vec<ApiHashProfile> {
    let mut profiles: Vec<ApiHashProfile> = bytes
        .windows(6)
        .enumerate()
        // Register-register IMUL with a trailing imm32. Requiring mod=3
        // makes bytes 2..6 unambiguously the multiplier.
        .filter(|(_, w)| w[0] == 0x69 && w[1] & 0xc0 == 0xc0)
        .filter_map(|(start, multiply)| {
            let byte_load = contains_after(bytes, start + 6, 16, |b| {
                b.len() >= 2 && b[..2] == [0x0f, 0xb6]
            })?;
            let xor_register = contains_after(bytes, byte_load + 2, 16, |b| {
                b.first().is_some_and(|op| matches!(*op, 0x31 | 0x33))
            })?;
            let xor_constant = contains_after(bytes, xor_register + 2, 16, |b| {
                b.len() >= 5 && b[0] == 0x35
            })?;
            let rotate = contains_after(bytes, xor_constant + 5, 16, |b| {
                // C1 /0 ib is ROL r32, imm8. Other C1 groups are shifts
                // or ROR and must not satisfy the existing ROL trait.
                b.len() >= 3 && b[0] == 0xc1 && b[1] & 0xc0 == 0xc0 && b[1] & 0x38 == 0 && b[2] < 32
            })?;
            let multiplier = u32::from_le_bytes(multiply[2..6].try_into().ok()?);
            let xor_value = u32::from_le_bytes(
                bytes
                    .get(xor_constant + 1..xor_constant + 5)?
                    .try_into()
                    .ok()?,
            );
            let seed_start = start.saturating_sub(64);
            let seed = bytes.get(seed_start..start).and_then(|prefix| {
                prefix
                    .windows(5)
                    .enumerate()
                    .rfind(|(_, window)| window[0] == 0xb8)
                    .and_then(|(_, window)| {
                        u32::from_le_bytes(window[1..5].try_into().ok()?).into()
                    })
            });
            let normalization_start = start.saturating_sub(32);
            let normalization = bytes.get(normalization_start..start).is_some_and(|prefix| {
                find_bytes(prefix, b"\x80\xcd\x20").len() == 1
                    && find_bytes(prefix, b"\x80\xf9\x1a").len() == 1
                    && prefix.windows(2).any(|window| window == [0x0f, 0x43])
            });
            Some(ApiHashProfile {
                loop_offset: start,
                kind: "multiply_xor_rotate",
                seed,
                multiplier,
                xor_constant: xor_value,
                rotate_bits: bytes[rotate + 2],
                ascii_lowercase: normalization,
            })
        })
        .collect();
    profiles.extend(find_xor_rotate_multiply_hash_profiles_x86(bytes));
    profiles.sort_by_key(|profile| profile.loop_offset);
    profiles.dedup_by_key(|profile| profile.loop_offset);
    profiles
}

/// Recover the alternate state update used by flattened resolvers:
///
/// `hash = (rol(hash ^ constant, bits) * multiplier) ^ lowercase(byte)`.
///
/// The seed may be initialized in a different dispatcher block. We only
/// report it when a concrete stack-slot copy connects the initialization to
/// the accumulator slot loaded by the loop.
fn find_xor_rotate_multiply_hash_profiles_x86(bytes: &[u8]) -> Vec<ApiHashProfile> {
    let mut profiles = Vec::new();
    for (multiply_offset, multiply) in bytes.windows(6).enumerate() {
        if multiply[0] != 0x69 || multiply[1] & 0xc0 != 0xc0 {
            continue;
        }
        let rotate_start = multiply_offset.saturating_sub(16);
        let Some((rotate_rel, rotate)) =
            bytes.get(rotate_start..multiply_offset).and_then(|prefix| {
                prefix.windows(3).enumerate().rfind(|(_, op)| {
                    op[0] == 0xc1 && op[1] & 0xc0 == 0xc0 && op[1] & 0x38 == 0 && op[2] < 32
                })
            })
        else {
            continue;
        };
        let rotate_offset = rotate_start + rotate_rel;
        let xor_start = rotate_offset.saturating_sub(12);
        let Some((xor_rel, _)) = bytes.get(xor_start..rotate_offset).and_then(|prefix| {
            prefix
                .windows(2)
                .enumerate()
                .rfind(|(_, op)| matches!(op[0], 0x31 | 0x33) && op[1] & 0xc0 == 0xc0)
        }) else {
            continue;
        };
        let xor_offset = xor_start + xor_rel;
        let constant_start = xor_offset.saturating_sub(10);
        let Some((_, constant_load)) = bytes.get(constant_start..xor_offset).and_then(|prefix| {
            prefix
                .windows(5)
                .enumerate()
                .rfind(|(_, op)| (0xb8..=0xbf).contains(&op[0]))
        }) else {
            continue;
        };
        let Some(byte_load) = contains_after(bytes, multiply_offset + 6, 16, |op| {
            op.len() >= 3 && op[..2] == [0x0f, 0xb6]
        }) else {
            continue;
        };
        let Some(_) = contains_after(bytes, byte_load + 3, 12, |op| {
            op.first().is_some_and(|byte| matches!(*byte, 0x31 | 0x33))
        }) else {
            continue;
        };

        let seed = recover_flattened_stack_hash_seed(bytes, xor_offset);
        let normalization_start = byte_load.saturating_sub(32);
        let normalization = bytes
            .get(normalization_start..byte_load)
            .is_some_and(|prefix| {
                find_bytes(prefix, b"\x80\xca\x20").len()
                    + find_bytes(prefix, b"\x80\xce\x20").len()
                    > 0
                    && prefix
                        .windows(3)
                        .any(|op| op[..2] == [0x80, 0xfa] && op[2] == 0x1a)
            });
        profiles.push(ApiHashProfile {
            loop_offset: byte_load,
            kind: "xor_rotate_multiply_xor",
            seed,
            multiplier: u32::from_le_bytes(multiply[2..6].try_into().unwrap_or([0; 4])),
            xor_constant: u32::from_le_bytes(constant_load[1..5].try_into().unwrap_or([0; 4])),
            rotate_bits: rotate[2],
            ascii_lowercase: normalization,
        });
    }
    profiles
}

fn recover_flattened_stack_hash_seed(bytes: &[u8], loop_offset: usize) -> Option<u32> {
    let search_start = loop_offset.saturating_sub(512);
    let prefix = bytes.get(search_start..loop_offset)?;

    // `mov accumulator, [esp+hash_slot]`
    let hash_slot = prefix
        .windows(4)
        .rfind(|op| op[0] == 0x8b && op[2] == 0x24)
        .map(|op| op[3])?;

    // Dispatcher transfer:
    // `mov eax,[esp+source_slot]; mov [esp+hash_slot],eax`.
    let source_slot = prefix
        .windows(8)
        .rfind(|op| {
            op[0..3] == [0x8b, 0x44, 0x24] && op[4..7] == [0x89, 0x44, 0x24] && op[7] == hash_slot
        })
        .map(|op| op[3])?;

    // Concrete initialization of that source slot.
    prefix
        .windows(8)
        .rfind(|op| op[0..3] == [0xc7, 0x44, 0x24] && op[3] == source_slot)
        .and_then(|op| u32::from_le_bytes(op[4..8].try_into().ok()?).into())
}

#[cfg(test)]
fn count_custom_byte_hash_loops_x86(bytes: &[u8]) -> usize {
    find_custom_byte_hash_profiles_x86(bytes).len()
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

/// Raw bytes of a named PE section (e.g. `.gopclntab`, `.rdata`), for
/// Go attribution recovery.
fn pe_section_bytes<'a>(pe: &PE<'_>, bytes: &'a [u8], name: &str) -> Option<&'a [u8]> {
    let section = pe.sections.iter().find(|s| s.name().ok() == Some(name))?;
    let start = section.pointer_to_raw_data as usize;
    let size = section.size_of_raw_data as usize;
    bytes.get(start..start.checked_add(size)?)
}

fn sections(pe: &PE<'_>, bytes: &[u8], _metrics: &mut Metrics, sections_out: &mut Vec<Section>) {
    for section in &pe.sections {
        let name = section.name().unwrap_or("").to_owned();
        let file_offset = u64::from(section.pointer_to_raw_data);
        let file_size = u64::from(section.size_of_raw_data);
        let entropy = (file_size > 0).then(|| section_entropy(bytes, file_offset, file_size));
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
            flags_raw: Some(u64::from(section.characteristics)),
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
    symbols_out: &mut crate::Symbols,
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
        symbols_out.push(crate::Symbol::Import {
            name: imp.name.to_string(),
            alias: None,
            library: Some(library),
            offset: Some(imp.offset as u64),
            ordinal: if name_is_ordinal_stub {
                Some(u32::from(imp.ordinal))
            } else {
                None
            },
        });
    }
    // Total import-symbol count flows through cross-format `imports.count`.
    // DLL dependencies (the libraries imports are bound to) flow through
    // cross-format `dependencies.count`.
    metrics.insert("dependencies.count", by_dll.len() as f64);

    if let Some(hash) = imphash(pe) {
        put_str(values, "pe.imphash", hash);
    }
}

fn exports(
    pe: &PE<'_>,
    values: &mut Values,
    metrics: &mut Metrics,
    symbols_out: &mut crate::Symbols,
) {
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
        symbols_out.push(crate::Symbol::Export {
            name: name.to_string(),
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
}

/// Locate the Certificate Table (Authenticode) directory, record its byte
/// count as `pe.cert_table_size`, and return the signature blob's
/// `(file_offset, size)`. `None` when the optional header has no cert-table
/// directory or it is empty — the shared front half of both Authenticode
/// readers below. For this directory alone the `virtual_address` is a true
/// file offset (a PE/COFF spec carve-out), so callers read the bytes directly.
fn cert_table_extent(opt: &OptionalHeader, metrics: &mut Metrics) -> Option<(usize, usize)> {
    let dir = opt.data_directories.get_certificate_table()?;
    if dir.size == 0 {
        return None;
    }
    metrics.insert("pe.cert_table_size", f64::from(dir.size));
    Some((dir.virtual_address as usize, dir.size as usize))
}

/// Authenticode lookup using only the parsed header — used when the
/// full goblin parse fails and we fall back to a header-only walk.
///
/// The presence of `pe.signatures` (or its absence) IS the "is the
/// binary signed?" answer — we don't emit a redundant boolean for it.
/// When the cert-table directory is set but the bytes are truncated
/// or refuse to parse, no `pe.signatures` entry is emitted; consumers
/// distinguish "no signature claim" from "claimed but unparseable" via
/// the secondary `pe.cert_table_size` marker.
fn authenticode_from_header(
    header: &goblin::pe::header::Header,
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
) {
    let Some(opt) = header.optional_header.as_ref() else {
        return;
    };
    let Some((offset, size)) = cert_table_extent(opt, metrics) else {
        return;
    };
    if offset.saturating_add(size) > bytes.len() {
        return;
    }
    super::pe_authenticode::parse(&bytes[offset..offset + size], values);
}

fn authenticode(pe: &PE<'_>, bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    // `pe.cert_table_size` is a byte count, so it is emitted as a metric (not a
    // value) — `type: metrics` trait conditions threshold on it. Presence of
    // `pe.signatures` remains the "is it signed" signal; a non-zero
    // cert_table_size with no parsed signatures means a claimed-but-unparseable
    // (tampered) signature.
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
    let Some((offset, size)) = cert_table_extent(opt, metrics) else {
        return;
    };
    // When the bytes the cert-table points at fall outside the file, the
    // header has been tampered with — emit a flag so downstream callers
    // don't have to redo the bounds check.
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
/// fingerprint. The lazy goblin walker can panic on truncated tables,
/// so we keep the parse self-contained (we already validated the
/// directory bounds before calling).
///
/// Emits to values:
/// - `pe.bound_imports[]` — array of `{name, time_date_stamp,
///   forwarder_ref_count}` objects, capped at 64 entries.
///
/// Emits to metrics:
/// - `pe.bound_import_count` — number of descriptors recovered.
/// - `pe.bound_imports_fingerprint` — CRC-32 of the canonical-sorted
///   set. Useful for "binaries linked on the same host within seconds
///   get the same fingerprint" clustering.
fn bound_imports(pe: &PE<'_>, bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
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

/// Raw PE data-directory declarations and structural inconsistencies.
///
/// Goblin deliberately treats a `(0, 0)` directory as absent, which is right
/// for normal extraction.  A directory with exactly one zero field is a
/// different case: it is declared in the optional header but cannot describe
/// a valid image range.  Packers and import-hiding loaders use this shape to
/// leave a misleading IAT/import declaration while presenting no parseable
/// imports.  Preserve it as a header fact instead of silently dropping it.
///
/// `pe.declared_data_directories[]` preserves every non-zero header slot with
/// its mapped section, even when the format parser declines to treat it as a
/// usable directory. `pe.data_directory_anomalies[]` holds the subset with a
/// zero RVA or size. The accompanying metrics are intentionally generic so
/// trait authors can detect malformed declarations without naming one
/// particular directory.
fn data_directory_anomalies(pe: &PE<'_>, bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    let Some(opt) = pe.header.optional_header.as_ref() else {
        return;
    };
    // The data-directory array begins 96 bytes into PE32 optional headers and
    // 112 bytes into PE32+ headers.  Read the original bytes rather than
    // goblin's sparse representation so malformed declared slots survive.
    let directory_relative_offset = match opt.standard_fields.magic {
        0x10b => 96_usize,
        0x20b => 112_usize,
        _ => return,
    };
    let Some(optional_offset) = (pe.header.dos_header.pe_pointer as usize).checked_add(4 + 20)
    else {
        return;
    };
    let Some(directory_offset) = optional_offset.checked_add(directory_relative_offset) else {
        return;
    };
    let directory_count = usize::try_from(opt.windows_fields.number_of_rva_and_sizes)
        .unwrap_or(16)
        .min(16);
    // Index → canonical name from the PE/COFF spec (winnt.h
    // IMAGE_DIRECTORY_ENTRY_*).  Kept local to avoid making this raw-header
    // recovery depend on goblin's sparse directory model.
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

    let mut declared = Vec::new();
    let mut anomalies = Vec::new();
    let mut zero_rva_nonzero_size = 0_u64;
    let mut nonzero_rva_zero_size = 0_u64;
    for (index, name) in NAMES.iter().enumerate().take(directory_count) {
        let Some(entry_offset) = directory_offset.checked_add(index.saturating_mul(8)) else {
            break;
        };
        let Some(entry) = bytes.get(entry_offset..entry_offset.saturating_add(8)) else {
            break;
        };
        let rva = u32::from_le_bytes(entry[..4].try_into().expect("fixed-width slice"));
        let size = u32::from_le_bytes(entry[4..].try_into().expect("fixed-width slice"));
        if rva == 0 && size == 0 {
            continue;
        }
        // Certificate-table addresses are file offsets by PE/COFF definition;
        // all other directory addresses are RVAs that can be mapped to a
        // section. Retain the mapping as a fact rather than assuming the
        // standard `.idata` / `.rsrc` / `.reloc` layout.
        let section = if index == 4 {
            None
        } else {
            pe.sections.iter().find_map(|s| {
                let start = s.virtual_address;
                let extent = s.virtual_size.max(s.size_of_raw_data);
                let end = start.saturating_add(extent);
                (rva >= start && rva < end)
                    .then(|| s.name().ok().map(str::to_owned))
                    .flatten()
            })
        };
        declared.push(serde_json::json!({
            "index": index,
            "name": name,
            "rva": rva,
            "size": size,
            "section": section,
        }));
        if rva != 0 && size != 0 {
            continue;
        }
        let kind = if rva == 0 {
            zero_rva_nonzero_size = zero_rva_nonzero_size.saturating_add(1);
            "zero_rva_nonzero_size"
        } else {
            nonzero_rva_zero_size = nonzero_rva_zero_size.saturating_add(1);
            "nonzero_rva_zero_size"
        };
        anomalies.push(serde_json::json!({
            "index": index,
            "name": name,
            "rva": rva,
            "size": size,
            "kind": kind,
        }));
    }
    // The count is unconditional; the list is not. An absent key is the right
    // shape for an empty value list, but as a metric it left a rule unable to
    // separate "declares no directory at all" from "never parsed". Zero is a
    // real and rare observation: every linker emits at least an import
    // directory, so a loadable image declaring none built its own header and
    // resolves imports at runtime.
    metrics.insert("pe.declared_data_directory_count", declared.len() as f64);
    if anomalies.is_empty() {
        if !declared.is_empty() {
            values.insert("pe.declared_data_directories", JsonValue::Array(declared));
        }
        return;
    }
    metrics.insert("pe.data_directory_anomaly_count", anomalies.len() as f64);
    if zero_rva_nonzero_size > 0 {
        metrics.insert(
            "pe.data_directory_zero_rva_nonzero_size_count",
            zero_rva_nonzero_size as f64,
        );
    }
    if nonzero_rva_zero_size > 0 {
        metrics.insert(
            "pe.data_directory_nonzero_rva_zero_size_count",
            nonzero_rva_zero_size as f64,
        );
    }
    values.insert("pe.declared_data_directories", JsonValue::Array(declared));
    values.insert("pe.data_directory_anomalies", JsonValue::Array(anomalies));
}

/// .NET / CLR metadata extracted from the COR20 header and metadata root.
/// The presence of `pe.clr` (or any sub-key) IS the "is this a managed
/// binary?" signal — distinct from PE Authenticode signing, which a managed
/// binary may or may not carry.
///
/// The fields answer the *who / what* of a managed build and are chosen to be
/// stable diff anchors: version-to-version differential analysis surfaces a
/// changed strong-name state, MVID, metadata version, or stream set, which is
/// how a trojanized release is told apart from a genuine rebuild.
///
/// Values (raw structural reads — strings, raw words, identities):
/// - `pe.clr.runtime_version`      — COR20 `"<major>.<minor>"` runtime version
/// - `pe.clr.metadata_version`     — metadata-root version string (e.g. `v4.0.30319`)
/// - `pe.clr.flags`                — raw COR20 flags word
/// - `pe.clr.entry_point_token`    — managed entry-point token (absent for a DLL)
/// - `pe.clr.mvid`                 — Module Version ID GUID; a build-unique
///   identity anchor for correlating and diffing releases (WHO / WHAT)
/// - `pe.clr.streams`              — metadata stream-name inventory. A shipped
///   release carrying `#-` (uncompressed / edit-and-continue tables) or
///   `#Schema` instead of the normal `#~` is a post-compile IL-patch tell.
///
/// Metrics (decoded flag bits / sizes — typed for comparison matching):
/// - `pe.clr.is_il_only`, `pe.clr.is_native_entrypoint`,
///   `pe.clr.is_32bit_required`, `pe.clr.is_32bit_preferred` — 0/1 COR20 bits
/// - `pe.clr.strong_name_signed`   — 0/1 COMIMAGE_FLAGS_STRONGNAMESIGNED (WHO /
///   integrity). A genuine vendor SDK is strong-name signed; a source-rebuilt
///   clone that never had the private key is not, so `0` under a vendor brand
///   is a forgery / publisher-hijack tell — and a `1 -> 0` transition across
///   versions is a strong differential signal.
/// - `pe.clr.strong_name_sig_size` — strong-name signature blob size (>0 with
///   `strong_name_signed=0` = delay-signed or signature stripped)
fn clr_metadata(pe: &PE<'_>, bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    use crate::formats::common::{put_str, put_u64};
    let Some(clr) = pe.clr_data.as_ref() else {
        return;
    };
    let hdr = &clr.cor20_header;
    // Raw structural reads (strings, raw words, identities) -> values.
    put_str(
        values,
        "pe.clr.runtime_version",
        format!(
            "{}.{}",
            hdr.major_runtime_version, hdr.minor_runtime_version
        ),
    );
    let mdver = clr.metadata_header.version.trim_matches('\0').trim();
    if !mdver.is_empty() {
        put_str(values, "pe.clr.metadata_version", mdver);
    }
    put_u64(values, "pe.clr.flags", u64::from(hdr.flags));
    if hdr.entry_point_token_or_rva != 0 {
        put_u64(
            values,
            "pe.clr.entry_point_token",
            u64::from(hdr.entry_point_token_or_rva),
        );
    }
    // Decoded flag bits and sizes are typed numbers -> metrics, so traits can
    // match them by comparison (e.g. `strong_name_signed max: 0`).
    let mut bit = |name: &str, v: bool| metrics.insert(name, f64::from(u8::from(v)));
    bit("pe.clr.is_il_only", hdr.is_il_only());
    bit("pe.clr.is_native_entrypoint", hdr.is_native_entrypoint());
    bit("pe.clr.is_32bit_required", hdr.is_32bit_required());
    bit("pe.clr.is_32bit_preferred", hdr.is_32bit_preferred());
    bit("pe.clr.strong_name_signed", hdr.is_strong_name_signed());
    if hdr.strong_name_signature.size > 0 {
        metrics.insert(
            "pe.clr.strong_name_sig_size",
            f64::from(hdr.strong_name_signature.size),
        );
    }
    // Parse the ECMA-335 metadata root directly. goblin 0.10's CLR stream
    // helpers (`sections()`/`mvid()`/`storage_header`) mis-seed the walk, and
    // its `metadata_data` is sliced from file offset 0 (the MZ header) rather
    // than the metadata RVA — both unusable — so resolve the metadata directory
    // ourselves and parse from the `BSJB` root.
    let mdir = hdr.metadata;
    let md = rva_to_file_offset(pe, mdir.virtual_address).and_then(|base| {
        let end = base.saturating_add(mdir.size as usize).min(bytes.len());
        bytes.get(base..end)
    });
    if let Some((names, guid_stream)) = md.and_then(parse_clr_streams) {
        if !names.is_empty() {
            let arr = names.into_iter().map(JsonValue::String).collect();
            values.insert("pe.clr.streams", JsonValue::Array(arr));
        }
        // The module MVID is the first GUID in the `#GUID` heap (Module.Mvid == 1).
        if let (Some((goff, gsize)), Some(md)) = (guid_stream, md) {
            if gsize >= 16 {
                if let Some(s) = md.get(goff..goff + 16).and_then(format_guid) {
                    put_str(values, "pe.clr.mvid", s);
                }
            }
        }
    }
}

/// Parse the .NET metadata-root stream directory (ECMA-335 II.24.2.1) from the
/// blob beginning at the `BSJB` signature. Returns the stream names in order
/// and the `(offset, size)` of the `#GUID` heap (offsets relative to the blob
/// start). Returns `None` when the signature or layout is malformed.
fn parse_clr_streams(md: &[u8]) -> Option<(Vec<String>, Option<(usize, usize)>)> {
    let rd_u32 = |b: &[u8], p: usize| -> Option<usize> {
        b.get(p..p + 4)
            .map(|s| u32::from_le_bytes(s.try_into().unwrap()) as usize)
    };
    if md.get(0..4)? != b"BSJB" {
        return None;
    }
    let version_len = rd_u32(md, 12)?;
    // Flags (u16) + Streams (u16) follow the 4-byte-padded version string.
    let mut p = 16usize.checked_add((version_len + 3) & !3)?;
    let n_streams = u16::from_le_bytes(md.get(p + 2..p + 4)?.try_into().unwrap());
    p += 4;
    let mut names = Vec::new();
    let mut guid_stream = None;
    for _ in 0..n_streams {
        let s_off = rd_u32(md, p)?;
        let s_size = rd_u32(md, p + 4)?;
        p += 8;
        // Name: null-terminated ASCII, whole field padded to a 4-byte boundary.
        let start = p;
        while *md.get(p)? != 0 {
            p += 1;
        }
        let name = std::str::from_utf8(&md[start..p]).ok()?.to_string();
        if name == "#GUID" {
            guid_stream = Some((s_off, s_size));
        }
        names.push(name);
        p = start.checked_add(((p - start) + 1 + 3) & !3)?;
    }
    Some((names, guid_stream))
}

/// Format a 16-byte .NET GUID (MVID) as the canonical
/// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` string. The first three fields are
/// stored little-endian and the last two byte-for-byte, matching how the CLR
/// (and `ikdasm`) render the module MVID.
fn format_guid(g: &[u8]) -> Option<String> {
    let g: &[u8; 16] = g.get(..16)?.try_into().ok()?;
    Some(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        g[3],
        g[2],
        g[1],
        g[0],
        g[5],
        g[4],
        g[7],
        g[6],
        g[8],
        g[9],
        g[10],
        g[11],
        g[12],
        g[13],
        g[14],
        g[15],
    ))
}

/// Measure the embedded managed (CLR) resources that the Win32 resource walk
/// never sees. The cor20 header's `Resources` directory points at a blob of
/// `[u32 little-endian length][bytes]` chunks (ECMA-335 II.25.3.3); each
/// embedded resource is one chunk. We don't need the `ManifestResource`
/// metadata table — names aside, the bytes are all here — so we skip the whole
/// table/heap machinery and just walk the blob. The forensic point is entropy:
/// .NET crypters stash an encrypted second stage as a managed resource, which
/// shows up as a high-entropy chunk among the low-entropy `.resources` streams.
///
/// Emits `pe.clr.managed_resource_{count, max_entropy, max_size}`.
fn clr_resources(pe: &PE<'_>, bytes: &[u8], metrics: &mut Metrics) {
    let Some(clr) = pe.clr_data.as_ref() else {
        return;
    };
    let dir = clr.cor20_header.resources;
    if dir.size == 0 {
        return;
    }
    let Some(base) = rva_to_file_offset(pe, dir.virtual_address) else {
        return;
    };
    let end = base.saturating_add(dir.size as usize).min(bytes.len());
    if base >= end {
        return;
    }

    let (count, max_entropy, max_size) = scan_resource_blob(&bytes[base..end]);
    if count == 0 {
        return;
    }
    metrics.insert("pe.clr.managed_resource_count", count as f64);
    metrics.insert("pe.clr.managed_resource_max_entropy", max_entropy);
    metrics.insert("pe.clr.managed_resource_max_size", max_size as f64);
}

/// Walk a CLR resources blob (`[u32 len][bytes]` chunks) and return
/// `(count, max_entropy, max_size)`. A length that runs past the blob stops the
/// walk — a corrupt or non-consecutive layout yields a short count, never a
/// panic or over-read.
fn scan_resource_blob(blob: &[u8]) -> (u64, f64, u64) {
    let (mut count, mut max_entropy, mut max_size, mut p) = (0u64, 0.0f64, 0u64, 0usize);
    while p + 4 <= blob.len() {
        let len = u32::from_le_bytes([blob[p], blob[p + 1], blob[p + 2], blob[p + 3]]) as usize;
        p += 4;
        if len == 0 || p + len > blob.len() {
            break;
        }
        max_entropy = max_entropy.max(entropy::shannon(&blob[p..p + len]));
        max_size = max_size.max(len as u64);
        count += 1;
        p += len;
    }
    (count, max_entropy, max_size)
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
        let name = section.name().unwrap_or("");
        let raw_end = u64::from(section.pointer_to_raw_data)
            .saturating_add(u64::from(section.size_of_raw_data));
        if section.size_of_raw_data > 0 && raw_end > file_size {
            overflow_names.push(name.to_string());
        }
        if file_alignment > 0
            && section.pointer_to_raw_data != 0
            && section.pointer_to_raw_data % file_alignment != 0
        {
            misaligned_names.push(name.to_string());
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
        let mut by_va: Vec<(u32, u32, &str)> = pe
            .sections
            .iter()
            .map(|s| {
                let span = s.virtual_size.max(s.size_of_raw_data);
                (
                    s.virtual_address,
                    s.virtual_address.saturating_add(span),
                    s.name().unwrap_or(""),
                )
            })
            .collect();
        by_va.sort_by_key(|t| t.0);
        let mut overlap_names: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for w in by_va.windows(2) {
            if w[0].1 > w[1].0 && w[1].0 >= w[0].0 {
                overlap_names.insert(w[0].2);
                overlap_names.insert(w[1].2);
            }
        }
        if !overlap_names.is_empty() {
            metrics.insert("pe.section_overlap_count", overlap_names.len() as f64);
            values.insert(
                "pe.overlapping_sections",
                JsonValue::Array(
                    overlap_names
                        .into_iter()
                        .map(|s| JsonValue::String(s.to_string()))
                        .collect(),
                ),
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
                    if t != 0 { t } else { rva as u64 }
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
            return section
                .pointer_to_raw_data
                .checked_add(delta)
                .map(|v| v as usize);
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
    // Emit `pe.checksum_valid` unconditionally — a `stored == 0`
    // value is itself a forensic signal (linker option `/RELEASE`
    // omitted, or post-build stripper / packer cleared the field).
    // `computed != 0` for any non-trivial binary, so `stored == 0`
    // reliably trips this comparison to `0.0`.
    metrics.insert("pe.checksum_valid", f64::from(u8::from(stored == computed)));
    if stored == 0 {
        metrics.insert("pe.checksum_stripped", 1.0);
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

/// Parse the IMAGE_LOAD_CONFIG_DIRECTORY structure using the `Size`
/// field embedded at offset 0 — Microsoft's spec says this is the
/// authoritative size, not the data-directory entry's `Size` field.
/// goblin's parser slices to `dd.size` and silently drops every field
/// past it, which on modern binaries truncates the parse before
/// `GuardFlags` (the CFG / mitigation status indicator).
///
/// Surfaces the security-cookie, the SafeSEH table, the full CFG /
/// Return Flow Guard / XFG pointer set, and a decoded
/// `IMAGE_GUARD_*` flag-name array. Field absence (`None`) is
/// preserved by omitting the key, so trait authors can distinguish
/// "field present and zero" (a cleared-cookie tampering tell) from
/// "field not in this binary's load_config".
fn load_config(pe: &PE<'_>, bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    use goblin::pe::optional_header::MAGIC_64;
    let Some(opt) = pe.header.optional_header.as_ref() else {
        return;
    };
    let Some(dd) = opt.data_directories.get_load_config_table() else {
        return;
    };
    if dd.virtual_address == 0 {
        return;
    }
    let Some(start) = rva_to_file_offset(pe, dd.virtual_address) else {
        return;
    };
    if start + 4 > bytes.len() {
        return;
    }
    let embedded_size = u32::from_le_bytes(bytes[start..start + 4].try_into().unwrap()) as usize;
    if embedded_size < 4 {
        return;
    }
    let end = start.saturating_add(embedded_size).min(bytes.len());
    let slice = &bytes[start..end];
    let is_64 = matches!(opt.standard_fields.magic, MAGIC_64);
    let mut obj = serde_json::Map::new();
    obj.insert("size".into(), JsonValue::Number(embedded_size.into()));

    let read_u32 = |off: usize| -> Option<u32> {
        slice
            .get(off..off + 4)
            .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
    };
    let read_u64 = |off: usize| -> Option<u64> {
        slice
            .get(off..off + 8)
            .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
    };
    let read_ptr = |off: usize| -> Option<u64> {
        if is_64 {
            read_u64(off)
        } else {
            read_u32(off).map(u64::from)
        }
    };

    // Field offsets per IMAGE_LOAD_CONFIG_DIRECTORY{32,64} from winnt.h.
    // Pre-cookie fields (TimeDateStamp, GlobalFlags, *Threshold, etc.)
    // are rarely forensically interesting and bloat the surface — we
    // skip straight to the security/mitigation-relevant block.
    let (
        sec_cookie,
        seh_table,
        seh_count,
        cf_check,
        cf_dispatch,
        cf_table,
        cf_count,
        guard_flags_off,
        taken_iat_table,
        taken_iat_count,
        longjmp_table,
        longjmp_count,
    ) = if is_64 {
        (
            0x58, 0x60, 0x68, 0x70, 0x78, 0x80, 0x88, 0x90, 0xA0, 0xA8, 0xB0, 0xB8,
        )
    } else {
        (
            0x3C, 0x40, 0x44, 0x48, 0x4C, 0x50, 0x54, 0x58, 0x68, 0x6C, 0x70, 0x74,
        )
    };

    let put_ptr =
        |obj: &mut serde_json::Map<String, JsonValue>, key: &str, off: usize, allow_zero: bool| {
            if let Some(v) = read_ptr(off) {
                if v != 0 || allow_zero {
                    obj.insert(key.into(), JsonValue::Number(v.into()));
                }
            }
        };
    put_ptr(&mut obj, "security_cookie", sec_cookie, true);
    put_ptr(&mut obj, "se_handler_table", seh_table, false);
    put_ptr(&mut obj, "se_handler_count", seh_count, false);
    put_ptr(&mut obj, "guard_cf_check_function_pointer", cf_check, false);
    put_ptr(
        &mut obj,
        "guard_cf_dispatch_function_pointer",
        cf_dispatch,
        false,
    );
    put_ptr(&mut obj, "guard_cf_function_table", cf_table, false);
    put_ptr(&mut obj, "guard_cf_function_count", cf_count, false);
    put_ptr(
        &mut obj,
        "guard_address_taken_iat_entry_table",
        taken_iat_table,
        false,
    );
    put_ptr(
        &mut obj,
        "guard_address_taken_iat_entry_count",
        taken_iat_count,
        false,
    );
    put_ptr(
        &mut obj,
        "guard_long_jump_target_table",
        longjmp_table,
        false,
    );
    put_ptr(
        &mut obj,
        "guard_long_jump_target_count",
        longjmp_count,
        false,
    );

    if let Some(flags) = read_u32(guard_flags_off) {
        // Both forms — raw u32 for round-trip and a string-flag array
        // for human-readable trait matches against `cf_instrumented`
        // / `cfw_instrumented`. Zero is still emitted; "no flags set"
        // is itself a meaningful signal ("CFG was not wired up").
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
        // Cross-format mitigation summary metrics — boolean-valued for
        // easy trait composition.
        let cf_on = flags & 0x0000_0100 != 0;
        metrics.insert("pe.has_cfg", f64::from(u8::from(cf_on)));
    }
    if read_ptr(seh_table).unwrap_or(0) != 0 && read_ptr(seh_count).unwrap_or(0) != 0 {
        metrics.insert("pe.has_safe_seh", 1.0);
    }

    values.insert("pe.load_config", JsonValue::Object(obj));
}

/// IMAGE_DELAYLOAD_DESCRIPTOR table walker. Delay-load imports are
/// resolved on first call rather than at process startup, so they
/// don't appear in the regular IAT / Import Directory — pefile sees
/// them via `DIRECTORY_ENTRY_DELAY_IMPORT`. They are forensically
/// important: evasive malware moves anti-analysis APIs
/// (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`,
/// `VirtualProtect` for code-patching, network primitives) into the
/// delay-load table so a static IAT scan misses them.
///
/// Emits `pe.delay_imports[]` (one descriptor per DLL with timestamp,
/// rva_based flag, and import count) and pushes each resolved symbol
/// into the typed [`Imports`] view with `source: "pe-delay"` so the
/// flattened import set matches what `dumpbin /dependents` would show.
fn delay_imports(
    pe: &PE<'_>,
    bytes: &[u8],
    values: &mut Values,
    metrics: &mut Metrics,
    symbols_out: &mut crate::Symbols,
) {
    use goblin::pe::optional_header::MAGIC_64;
    let Some(opt) = pe.header.optional_header.as_ref() else {
        return;
    };
    let Some(dd) = opt.data_directories.get_delay_import_descriptor() else {
        return;
    };
    if dd.virtual_address == 0 || dd.size == 0 {
        return;
    }
    let Some(table_off) = rva_to_file_offset(pe, dd.virtual_address) else {
        return;
    };
    let is_64 = matches!(opt.standard_fields.magic, MAGIC_64);
    let ptr_size = if is_64 { 8 } else { 4 };
    let image_base = opt.windows_fields.image_base;
    const DESC_SIZE: usize = 32; // IMAGE_DELAYLOAD_DESCRIPTOR is 8 DWORDs
    const MAX_DESCRIPTORS: usize = 128;
    const MAX_FUNCTIONS_PER_DLL: usize = 4096;

    let mut entries_out: Vec<JsonValue> = Vec::new();
    let mut total_imports = 0_u64;
    let mut cursor = table_off;
    let mut desc_idx = 0;
    while desc_idx < MAX_DESCRIPTORS && cursor + DESC_SIZE <= bytes.len() {
        let attrs = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
        let name_va = u32::from_le_bytes(bytes[cursor + 4..cursor + 8].try_into().unwrap());
        // Skip ModuleHandle (offset 8) — runtime cache, no forensic value.
        let _iat_va = u32::from_le_bytes(bytes[cursor + 12..cursor + 16].try_into().unwrap());
        let int_va = u32::from_le_bytes(bytes[cursor + 16..cursor + 20].try_into().unwrap());
        // BoundIAT, UnloadIAT — also runtime caches.
        let timestamp = u32::from_le_bytes(bytes[cursor + 28..cursor + 32].try_into().unwrap());
        cursor += DESC_SIZE;
        desc_idx += 1;

        if attrs == 0 && name_va == 0 && int_va == 0 {
            break; // all-zero descriptor terminates the list
        }
        // Attributes bit 0 (`RvaBased`) tells us whether `name`/`iat`/`int`
        // are RVAs (modern linkers) or absolute VAs (legacy / VC6 era).
        let rva_based = attrs & 1 != 0;
        let to_rva = |v: u32| -> u32 {
            if rva_based {
                v
            } else {
                v.saturating_sub(image_base as u32)
            }
        };

        let dll = read_cstring_at_rva(pe, bytes, to_rva(name_va));
        if dll.is_empty() {
            continue;
        }
        let lib_lower = dll.to_ascii_lowercase();
        let library = strip_lib_ext(&lib_lower).to_string();

        // Walk the Import Name Table — array of pointer-sized entries.
        // High bit = ordinal-only (low 16 bits is the ordinal); else
        // RVA pointing at an IMAGE_IMPORT_BY_NAME { hint:WORD, name:cstr }.
        let mut function_count = 0_u64;
        if let Some(mut int_off) = rva_to_file_offset(pe, to_rva(int_va)) {
            let ordinal_mask: u64 = if is_64 {
                0x8000_0000_0000_0000
            } else {
                0x8000_0000
            };
            for _ in 0..MAX_FUNCTIONS_PER_DLL {
                if int_off + ptr_size > bytes.len() {
                    break;
                }
                // Keep the file offset of the INT entry before advancing.
                // Delay imports are real symbol evidence too; dropping this
                // offset leaves symbol matches with only the semantic
                // `"import"` location, so cleave cannot anchor their context.
                let entry_off = int_off;
                let entry = if is_64 {
                    u64::from_le_bytes(bytes[int_off..int_off + 8].try_into().unwrap())
                } else {
                    u64::from(u32::from_le_bytes(
                        bytes[int_off..int_off + 4].try_into().unwrap(),
                    ))
                };
                int_off += ptr_size;
                if entry == 0 {
                    break;
                }
                if entry & ordinal_mask != 0 {
                    let ordinal = (entry & 0xFFFF) as u32;
                    symbols_out.push(crate::Symbol::Import {
                        name: format!("ORDINAL {ordinal}"),
                        alias: None,
                        library: Some(library.clone()),
                        offset: Some(entry_off as u64),
                        ordinal: Some(ordinal),
                    });
                } else {
                    let name = read_hint_name(pe, bytes, entry as u32);
                    if !name.is_empty() {
                        symbols_out.push(crate::Symbol::Import {
                            name,
                            alias: None,
                            library: Some(library.clone()),
                            offset: Some(entry_off as u64),
                            ordinal: None,
                        });
                    }
                }
                function_count += 1;
            }
        }
        total_imports = total_imports.saturating_add(function_count);

        entries_out.push(serde_json::json!({
            "dll": dll,
            "rva_based": rva_based,
            "time_date_stamp": timestamp,
            "import_count": function_count,
        }));
    }

    if !entries_out.is_empty() {
        values.insert("pe.delay_imports", JsonValue::Array(entries_out));
        metrics.insert("pe.delay_import_count", total_imports as f64);
    }
}

/// Read a NUL-terminated C string at the given RVA. Returns an empty
/// string if the RVA doesn't map into any section or the bytes aren't
/// UTF-8 (DLL names and function names are ASCII by spec).
fn read_cstring_at_rva(pe: &PE<'_>, bytes: &[u8], rva: u32) -> String {
    let Some(off) = rva_to_file_offset(pe, rva) else {
        return String::new();
    };
    read_cstring_at_rva_inner(bytes, off)
}

/// Read an IMAGE_IMPORT_BY_NAME { hint: WORD, name: CSTR } at the
/// given RVA, returning just the name (the hint is a linker artefact
/// not forensically interesting).
fn read_hint_name(pe: &PE<'_>, bytes: &[u8], rva: u32) -> String {
    let Some(off) = rva_to_file_offset(pe, rva) else {
        return String::new();
    };
    if off + 2 >= bytes.len() {
        return String::new();
    }
    read_cstring_at_rva_inner(bytes, off + 2)
}

/// Read a NUL-terminated, UTF-8 (ASCII by spec) string at a file offset,
/// capped at 512 bytes. The shared core of both RVA-string readers.
fn read_cstring_at_rva_inner(bytes: &[u8], off: usize) -> String {
    let cap = bytes.len().min(off.saturating_add(512));
    if off >= cap {
        return String::new();
    }
    let tail = &bytes[off..cap];
    let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
    std::str::from_utf8(&tail[..end]).unwrap_or("").to_string()
}

/// Walk the base-relocation directory (data dir index 5) and count
/// the relocation entries. ASLR-aware binaries carry a populated
/// relocation table; packed / hand-rolled binaries often strip or
/// truncate it. The block structure is a sequence of
/// `IMAGE_BASE_RELOCATION { page_rva: DWORD, block_size: DWORD }`
/// each followed by `(block_size-8)/2` WORD entries (4-bit type +
/// 12-bit offset).
fn base_relocations(pe: &PE<'_>, bytes: &[u8], values: &mut Values, metrics: &mut Metrics) {
    let Some(opt) = pe.header.optional_header.as_ref() else {
        return;
    };
    let Some(dd) = opt.data_directories.get_base_relocation_table() else {
        return;
    };
    if dd.virtual_address == 0 || dd.size == 0 {
        return;
    }
    let Some(start) = rva_to_file_offset(pe, dd.virtual_address) else {
        return;
    };
    let end = start.saturating_add(dd.size as usize).min(bytes.len());
    let mut cursor = start;
    let mut block_count = 0_u64;
    let mut entry_count = 0_u64;
    let mut absolute_count = 0_u64; // type 0 — pure padding, no real reloc
    while cursor + 8 <= end {
        let _page_rva = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
        let block_size =
            u32::from_le_bytes(bytes[cursor + 4..cursor + 8].try_into().unwrap()) as usize;
        if block_size < 8 || cursor + block_size > end {
            break;
        }
        block_count += 1;
        let entries = (block_size - 8) / 2;
        for i in 0..entries {
            let off = cursor + 8 + i * 2;
            if off + 2 > end {
                break;
            }
            let word = u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap());
            let kind = word >> 12;
            if kind == 0 {
                absolute_count += 1;
            } else {
                entry_count += 1;
            }
        }
        cursor += block_size;
    }
    if block_count > 0 {
        values.insert(
            "pe.base_relocations",
            serde_json::json!({
                "block_count": block_count,
                "entry_count": entry_count,
                "padding_count": absolute_count,
            }),
        );
        metrics.insert("pe.base_relocation_block_count", block_count as f64);
        metrics.insert("pe.base_relocation_entry_count", entry_count as f64);
    }

    // Reloc-section overhang: how much of the section that hosts the base-
    // relocation directory is NOT actual relocation data. Real relocation
    // tables fill their `.reloc` section (modulo a sub-alignment tail). Packers
    // and trojanized loaders append an encrypted second stage to `.reloc` so the
    // section dwarfs the few real relocation blocks — the parser stops at the
    // first malformed block (or the directory end) far short of the section's
    // raw size. `overhang_ratio` is that gap as a fraction of the section, a
    // precise, format-level "payload concealed in .reloc" signal that does not
    // depend on the payload's entropy. ~0 for benign images.
    let parsed_bytes = (cursor - start) as u64;
    if let Some(section) = pe.sections.iter().find(|s| {
        let va = u64::from(s.virtual_address);
        let span = u64::from(s.virtual_size).max(u64::from(s.size_of_raw_data));
        let dir_va = u64::from(dd.virtual_address);
        dir_va >= va && dir_va < va.saturating_add(span)
    }) {
        let section_raw = u64::from(section.size_of_raw_data);
        if section_raw > 0 {
            let overhang = section_raw.saturating_sub(parsed_bytes);
            metrics.insert("pe.reloc_overhang_bytes", overhang as f64);
            metrics.insert(
                "pe.reloc_overhang_ratio",
                overhang as f64 / section_raw as f64,
            );
        }
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
    if flags & 0x0001_0000 != 0 {
        out.push("longjump_table_present");
    }
    if flags & 0x0002_0000 != 0 {
        out.push("rf_instrumented");
    }
    if flags & 0x0004_0000 != 0 {
        out.push("rf_enable");
    }
    if flags & 0x0008_0000 != 0 {
        out.push("rf_strict");
    }
    if flags & 0x0010_0000 != 0 {
        out.push("retpoline_present");
    }
    if flags & 0x0040_0000 != 0 {
        out.push("eh_continuation_table_present");
    }
    if flags & 0x0080_0000 != 0 {
        out.push("xfg_enabled");
    }
    if flags & 0x0100_0000 != 0 {
        out.push("castguard_present");
    }
    if flags & 0x0200_0000 != 0 {
        out.push("memcpy_present");
    }
    out
}

/// `IMAGE_RESOURCE_DIRECTORY.TimeDateStamp` — independent of the COFF
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
    fn format_guid_renders_mvid_like_ikdasm() {
        // #GUID heap bytes (first three fields little-endian) for the MVID
        // ikdasm prints as {3C2F06E5-115F-41C1-9886-1F7748FBEF06}.
        let bytes = [
            0xe5, 0x06, 0x2f, 0x3c, 0x5f, 0x11, 0xc1, 0x41, 0x98, 0x86, 0x1f, 0x77, 0x48, 0xfb,
            0xef, 0x06,
        ];
        assert_eq!(
            format_guid(&bytes).as_deref(),
            Some("3c2f06e5-115f-41c1-9886-1f7748fbef06")
        );
        assert_eq!(format_guid(&[0u8; 8]), None);
    }

    #[test]
    fn parse_clr_streams_reads_standard_heaps() {
        // Minimal metadata root: BSJB, version "v4.0" (len 4), flags=0,
        // streams=2, then #GUID (offset 0x20, size 16) and #Blob headers.
        let mut md = Vec::new();
        md.extend_from_slice(b"BSJB");
        md.extend_from_slice(&1u16.to_le_bytes()); // major
        md.extend_from_slice(&1u16.to_le_bytes()); // minor
        md.extend_from_slice(&0u32.to_le_bytes()); // reserved
        md.extend_from_slice(&4u32.to_le_bytes()); // version_len
        md.extend_from_slice(b"v4.0"); // version (already 4-aligned)
        md.extend_from_slice(&0u16.to_le_bytes()); // flags
        md.extend_from_slice(&2u16.to_le_bytes()); // streams
        md.extend_from_slice(&0x20u32.to_le_bytes()); // #GUID offset
        md.extend_from_slice(&16u32.to_le_bytes()); // #GUID size
        md.extend_from_slice(b"#GUID\0\0\0"); // name, padded to 8
        md.extend_from_slice(&0x40u32.to_le_bytes()); // #Blob offset
        md.extend_from_slice(&8u32.to_le_bytes()); // #Blob size
        md.extend_from_slice(b"#Blob\0\0\0"); // name, padded to 8
        let (names, guid) = parse_clr_streams(&md).unwrap();
        assert_eq!(names, vec!["#GUID".to_string(), "#Blob".to_string()]);
        assert_eq!(guid, Some((0x20, 16)));
        assert!(parse_clr_streams(&b"NOPE"[..]).is_none());
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
        let mut symbols = crate::Symbols::new();
        let mut errors = Errors::new();
        let _ = extract(
            bytes,
            &mut v,
            &mut s,
            &mut m,
            &mut sections,
            &mut symbols,
            &mut errors,
        );
        (v, s, m)
    }

    fn read_fixture(name: &str) -> Vec<u8> {
        let path = format!("tests/fixtures/{name}");
        std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {path}: {e}"))
    }

    #[test]
    fn malformed_declared_directory_is_preserved_as_a_fact() {
        let mut bytes = read_fixture("test.exe");
        let pe_offset = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
        let optional_offset = pe_offset + 24;
        let directory_offset = match u16::from_le_bytes(
            bytes[optional_offset..optional_offset + 2]
                .try_into()
                .unwrap(),
        ) {
            0x10b => optional_offset + 96,
            0x20b => optional_offset + 112,
            magic => panic!("unexpected fixture optional-header magic {magic:#x}"),
        };
        // Import directory: zero RVA with non-zero declared size. This must
        // not disappear just because the normal import walker cannot use it.
        let import_offset = directory_offset + 8;
        bytes[import_offset..import_offset + 4].fill(0);
        bytes[import_offset + 4..import_offset + 8].copy_from_slice(&0x40_u32.to_le_bytes());

        let (values, _, metrics) = run(&bytes);
        let anomalies = values
            .get("pe.data_directory_anomalies")
            .and_then(serde_json::Value::as_array)
            .expect("malformed directory must be preserved");
        assert!(anomalies.iter().any(|entry| {
            entry.get("name").and_then(serde_json::Value::as_str) == Some("import")
                && entry.get("kind").and_then(serde_json::Value::as_str)
                    == Some("zero_rva_nonzero_size")
        }));
        assert_eq!(
            metrics.get("pe.data_directory_zero_rva_nonzero_size_count"),
            Some(1.0)
        );
    }

    #[test]
    fn manual_resolver_code_signals_require_the_complete_mechanics() {
        // A bounds-checking export walker: MZ → e_lfanew → PE signature →
        // PE32 export-directory offset and size. Keep this independent from a fixture
        // so a future parser change cannot accidentally widen the detector.
        let checked_walk = [
            0x66, 0x81, 0x3f, 0x4d, 0x5a, 0x8b, 0x47, 0x3c, 0x81, 0x3c, 0x07, 0x50, 0x45, 0x00,
            0x00, 0x8b, 0x4c, 0x07, 0x78, 0x8b, 0x54, 0x07, 0x7c,
        ];
        assert_eq!(count_checked_export_walks_x86(&checked_walk), 1);
        assert_eq!(
            find_checked_export_walks_x86(&checked_walk),
            vec![CheckedExportWalk {
                mz_check: 0,
                e_lfanew: 5,
                pe_check: 8,
                export_rva: 15,
                export_size: 19,
            }]
        );
        assert_eq!(count_checked_export_walks_x86(&checked_walk[..8]), 0);

        // A byte-wise custom hash: multiply, byte load, XOR with the
        // accumulator and a constant, then rotate.
        let hash_loop = [
            0xb8, 0xdb, 0xf7, 0x26, 0xab, 0x80, 0xcd, 0x20, 0x80, 0xf9, 0x1a, 0x0f, 0x43, 0xcb,
            0x69, 0xd8, 0x7f, 0x85, 0x3b, 0x80, 0x0f, 0xb6, 0xc1, 0x31, 0xd8, 0x35, 0x38, 0x9f,
            0x93, 0x87, 0xc1, 0xc0, 0x09,
        ];
        assert_eq!(count_custom_byte_hash_loops_x86(&hash_loop), 1);
        assert_eq!(
            find_custom_byte_hash_profiles_x86(&hash_loop),
            vec![ApiHashProfile {
                loop_offset: 14,
                kind: "multiply_xor_rotate",
                seed: Some(0xab26f7db),
                multiplier: 0x803b857f,
                xor_constant: 0x87939f38,
                rotate_bits: 9,
                ascii_lowercase: true,
            }]
        );
        assert_eq!(count_custom_byte_hash_loops_x86(&hash_loop[..29]), 0);
    }

    #[test]
    fn flattened_xor_rotate_multiply_hash_profile_recovers_seed_flow() {
        let hash_loop = [
            // seed -> stack slot 0x10
            0xc7, 0x44, 0x24, 0x10, 0xb5, 0xcf, 0x88, 0x11,
            // dispatcher copies slot 0x10 -> accumulator slot 0x1c
            0x8b, 0x44, 0x24, 0x10, 0x89, 0x44, 0x24, 0x1c,
            // lowercase normalization and accumulator update
            0x8b, 0x44, 0x24, 0x18, 0x0f, 0xb6, 0x0c, 0x07, 0x89, 0xca, 0x80, 0xc2, 0xbf, 0x88,
            0xce, 0x80, 0xce, 0x20, 0x80, 0xfa, 0x1a, 0x0f, 0xb6, 0xd6, 0x0f, 0x43, 0xd1, 0x8b,
            0x4c, 0x24, 0x1c, 0xbd, 0xa7, 0x79, 0x02, 0x34, 0x31, 0xe9, 0xc1, 0xc1, 0x15, 0x69,
            0xc9, 0x59, 0x94, 0x27, 0x85, 0x0f, 0xb6, 0xd2, 0x31, 0xca,
        ];
        let profiles = find_custom_byte_hash_profiles_x86(&hash_loop);
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].kind, "xor_rotate_multiply_xor");
        assert_eq!(profiles[0].seed, Some(0x1188cfb5));
        assert_eq!(profiles[0].xor_constant, 0x340279a7);
        assert_eq!(profiles[0].multiplier, 0x85279459);
        assert_eq!(profiles[0].rotate_bits, 21);
        assert!(profiles[0].ascii_lowercase);
    }

    #[test]
    fn recovered_profile_exactly_matches_native_api_name() {
        let profile = LocatedHashProfile {
            va: 0x40ed6d,
            kind: "xor_rotate_multiply_xor".to_string(),
            seed: 0x1188cfb5,
            multiplier: 0x85279459,
            xor_constant: 0x340279a7,
            rotate_bits: 21,
            ascii_lowercase: true,
        };
        assert_eq!(
            hash_windows_name(&profile, "NtQueryInformationProcess"),
            0x3b1471e8
        );
        assert_ne!(
            hash_windows_name(&profile, "NtQuerySystemInformation"),
            0x3b1471e8
        );
    }

    #[test]
    fn recovers_immediate_and_constant_folded_hash_arguments() {
        let mut bytes = read_fixture("test.exe");
        let pe_offset = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
        let optional_offset = pe_offset + 24;
        assert_eq!(
            u16::from_le_bytes(
                bytes[optional_offset..optional_offset + 2]
                    .try_into()
                    .unwrap()
            ),
            0x20b
        );
        bytes[optional_offset + 24..optional_offset + 32]
            .copy_from_slice(&0x0040_0000_u64.to_le_bytes());
        let pe = PE::parse(&bytes).expect("fixture PE");
        let section = pe
            .sections
            .iter()
            .find(|section| section.size_of_raw_data >= 0x100)
            .expect("fixture code section");
        let section_file = section.pointer_to_raw_data as usize;
        let section_va = pe.image_base + u64::from(section.virtual_address);
        drop(pe);

        let direct_offset = section_file + 0x20;
        bytes[direct_offset..direct_offset + 11]
            .copy_from_slice(&[0x68, 0xe8, 0x71, 0x14, 0x3b, 0x50, 0xe8, 0, 0, 0, 0]);

        let memory_offset = section_file + 0x80;
        bytes[memory_offset..memory_offset + 4].copy_from_slice(&0x0000bd87_u32.to_le_bytes());
        let memory_va = u32::try_from(section_va + 0x80).expect("PE32 fixture VA");
        let folded_offset = section_file + 0x40;
        let mut folded = vec![0xa1];
        folded.extend_from_slice(&memory_va.to_le_bytes());
        folded.push(0xb9);
        folded.extend_from_slice(&0x9bf7790b_u32.to_le_bytes());
        folded.extend_from_slice(&[0x31, 0xc8, 0x05]);
        folded.extend_from_slice(&0x9f1cad5c_u32.to_le_bytes());
        folded.extend_from_slice(&[0x50, 0xff, 0x74, 0x24, 0x0c, 0xe8, 0, 0, 0, 0]);
        bytes[folded_offset..folded_offset + folded.len()].copy_from_slice(&folded);
        let pe = PE::parse(&bytes).expect("mutated fixture PE");
        assert_eq!(
            recover_x86_hash_argument(&pe, &bytes, section_va + 0x26),
            Some((0x3b1471e8, "immediate"))
        );
        assert_eq!(
            recover_x86_hash_argument(&pe, &bytes, section_va + 0x40 + 22),
            Some((0x3b1471e8, "constant_folded_memory_xor_add"))
        );
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

    // Managed CLR extraction, end to end, against tiny C# libraries built from
    // the same source with and without `csc /keyfile` (see tests/fixtures).
    #[test]
    fn clr_unsigned_fixture_reports_no_strong_name() {
        let (v, _, m) = run(&read_fixture("managed-unsigned.dll"));
        // STRONGNAMESIGNED bit clear -> metric 0 (the forgery-relevant state).
        assert_eq!(m.get("pe.clr.strong_name_signed"), Some(0.0));
        assert_eq!(m.get("pe.clr.is_il_only"), Some(1.0));
        assert_eq!(
            v.get("pe.clr.metadata_version").and_then(JsonValue::as_str),
            Some("v4.0.30319")
        );
        // MVID is a well-formed lowercase 8-4-4-4-12 GUID.
        let mvid = v
            .get("pe.clr.mvid")
            .and_then(JsonValue::as_str)
            .expect("mvid present");
        assert_eq!(mvid.len(), 36);
        assert_eq!(mvid.matches('-').count(), 4);
        assert!(mvid.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
        // Standard heaps, in order; a `#-`/`#Schema` stream would signal IL patching.
        let streams: Vec<&str> = v
            .get("pe.clr.streams")
            .and_then(JsonValue::as_array)
            .expect("streams present")
            .iter()
            .filter_map(JsonValue::as_str)
            .collect();
        assert_eq!(streams, ["#~", "#Strings", "#US", "#GUID", "#Blob"]);
    }

    #[test]
    fn clr_signed_fixture_reports_strong_name() {
        // Same source, strong-name signed: the STRONGNAMESIGNED bit flips the metric.
        let (_, _, m) = run(&read_fixture("managed-signed.dll"));
        assert_eq!(m.get("pe.clr.strong_name_signed"), Some(1.0));
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
        let mut symbols = crate::Symbols::new();
        let mut errors = Errors::new();
        extract(
            &bytes,
            &mut v,
            &mut s,
            &mut m,
            &mut sections,
            &mut symbols,
            &mut errors,
        )
        .unwrap();
        for sym in symbols.iter_kind(crate::SymbolKind::Export) {
            if let crate::Symbol::Export { forward_to, .. } = sym {
                assert!(
                    forward_to.is_none(),
                    "test.exe shouldn't have forwarded exports; got {forward_to:?}",
                );
            }
        }
        assert!(m.get("pe.forwarded_export_count").is_none());
    }

    /// Verifies the unified Symbols view is populated for PE imports and
    /// that library names are normalised (lowercase, no `.dll`).
    #[test]
    fn typed_imports_and_exports_populated() {
        let bytes = read_fixture("test.exe");
        let mut v = Values::new();
        let mut s = Strings::default();
        let mut m = Metrics::new();
        let mut sections = Vec::new();
        let mut symbols = crate::Symbols::new();
        let mut errors = Errors::new();
        extract(
            &bytes,
            &mut v,
            &mut s,
            &mut m,
            &mut sections,
            &mut symbols,
            &mut errors,
        )
        .unwrap();
        let imports: Vec<&crate::Symbol> = symbols.iter_kind(crate::SymbolKind::Import).collect();
        assert!(!imports.is_empty(), "expected at least one PE import");
        for sym in imports {
            let crate::Symbol::Import { library, .. } = sym else {
                unreachable!("iter_kind(Import) yields only Import variants");
            };
            let lib = library.as_deref().expect("PE imports carry library");
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

    /// Build a CLR resources blob from `[u32 len][bytes]` chunks.
    fn resource_blob(chunks: &[&[u8]]) -> Vec<u8> {
        let mut b = Vec::new();
        for c in chunks {
            b.extend_from_slice(&(c.len() as u32).to_le_bytes());
            b.extend_from_slice(c);
        }
        b
    }

    #[test]
    fn scan_resource_blob_counts_and_measures() {
        let low = vec![b'A'; 256]; // entropy 0
        let high: Vec<u8> = (0..=255u8).cycle().take(4096).collect(); // entropy ~8
        let blob = resource_blob(&[&low, &high]);
        let (count, max_entropy, max_size) = scan_resource_blob(&blob);
        assert_eq!(count, 2);
        assert_eq!(max_size, 4096);
        assert!(max_entropy > 7.0, "max_entropy {max_entropy}");
    }

    #[test]
    fn scan_resource_blob_stops_on_bad_length() {
        // One good chunk, then a length that overruns the blob — the walk
        // counts the good chunk and stops rather than over-reading.
        let mut blob = resource_blob(&[b"hello there friend"]);
        blob.extend_from_slice(&u32::MAX.to_le_bytes());
        blob.extend_from_slice(b"trailing");
        let (count, _, max_size) = scan_resource_blob(&blob);
        assert_eq!(count, 1);
        assert_eq!(max_size, 18);
    }

    #[test]
    fn scan_resource_blob_empty_and_truncated() {
        assert_eq!(scan_resource_blob(&[]), (0, 0.0, 0));
        assert_eq!(scan_resource_blob(&[0x10, 0x00]), (0, 0.0, 0)); // < 4 bytes
    }
}
