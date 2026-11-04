//! PE / COFF (Portable Executable) extractor.
//!
//! Reads Windows executables, DLLs, sys drivers, and CRX-wrapped PEs.
//! Surfaces COFF header fields, the optional-header subsystem and
//! characteristics, the section table, imports and exports, the
//! resources, Authenticode, and the managed (CLR) metadata when present.
//!
//! The schema follows the names PE-the-format gives its own fields,
//! lightly snake-cased. `IMAGE_FILE_HEADER.Machine` becomes
//! `pe.machine`; `IMAGE_OPTIONAL_HEADER.Subsystem` becomes
//! `pe.subsystem`. Symbol tables live in the typed imports /
//! exports views rather than being mirrored into `values`.

mod anomalies;
mod api_hash;
mod clr;
mod debug;
mod exports;
mod headers;
pub(super) mod imports;
pub(super) mod layout;
mod load_config;
mod manifest;
mod ordinals;
mod relocations;
mod resources;
pub(super) mod rich;
mod signature;
mod version_info;

use goblin::pe::PE;

use crate::error::Error;
use crate::formats::common::{
    XorScan, apply_native, extract_binary_strings, extract_binary_strings_from_object, native,
    recover_natively, recovered_counts,
};
use crate::formats::goblin_safe;
use crate::metric;
use crate::value_key;

pub(super) fn extract(bytes: &[u8], ctx: super::ExtractCtx<'_>) -> Result<(), Error> {
    // goblin is handed the bytes with the structures it cannot survive
    // cleared (see `goblin_safe::prepare_pe`); every raw reader — section
    // data, overlay, Authenticode, the Rich header — keeps reading the
    // untouched `bytes`. What had to be given up is a fact about the sample,
    // so it lands in the errors view: an empty import or export view then
    // reads as a forged table rather than as a binary that has none.
    let prepared = goblin_safe::prepare_pe(bytes);
    if let Some(reason) = prepared.exports_skipped {
        ctx.errors
            .record_malformed(crate::Stage::PeParse, reason.to_string());
    }
    if let Some(reason) = prepared.imports_skipped {
        ctx.errors
            .record_malformed(crate::Stage::PeParse, reason.to_string());
        ctx.metrics
            .insert(metric!("pe.import_table_unwalkable"), 1.0);
    }

    // The full parse gives imports, exports, resources and the section table
    // in one go. Its failure is recorded before the header-only fallback, so
    // consumers see which stage tripped even when the fallback succeeds.
    match goblin_safe::parse_pe(&prepared) {
        goblin_safe::GoblinOutcome::Ok(pe) => {
            parsed(pe, bytes, ctx);
            return Ok(());
        }
        goblin_safe::GoblinOutcome::Failed(e) => {
            tracing::debug!(
                target: "filefacts::pe",
                format = "pe",
                stage = "parse",
                len = bytes.len(),
                error = %e,
                "full PE parse failed; falling back to the headers"
            );
            ctx.errors
                .record_malformed(crate::Stage::PeParse, e.to_string());
            ctx.metrics.insert(metric!("pe.parse_failed"), 1.0);
        }
        goblin_safe::GoblinOutcome::Panicked(msg) => {
            tracing::debug!(
                target: "filefacts::pe",
                format = "pe",
                stage = "parse",
                len = bytes.len(),
                error = %msg,
                "full PE parse panicked; falling back to the headers"
            );
            ctx.errors.record_panic(crate::Stage::PeParse, msg);
            ctx.metrics.insert(metric!("pe.parse_panicked"), 1.0);
        }
    }
    header_only(&prepared.bytes, bytes, ctx)
}

/// Every fact a full goblin parse supports.
fn parsed(pe: PE<'_>, bytes: &[u8], ctx: super::ExtractCtx<'_>) {
    let super::ExtractCtx {
        values,
        strings,
        metrics,
        sections: sections_out,
        symbols: symbols_out,
        errors: errors_out,
        ..
    } = ctx;
    // One stng pass covers ASCII, section names and the UTF-16 resource and
    // version-info runs, at absolute file offsets. It takes the parse as an
    // Object, moved in and back out, so the binary is not parsed twice.
    let object = goblin::Object::PE(pe);
    extract_binary_strings_from_object(&object, bytes, strings, XorScan::Yes);
    // Constructed as `Object::PE` two lines up.
    let goblin::Object::PE(pe) = object else {
        return;
    };
    let pe = &pe;
    headers::coff_header(&pe.header.coff_header, values, metrics);
    headers::dos_header(&pe.header, values);
    if let Some(ref opt) = pe.header.optional_header {
        headers::optional_header(opt, values, metrics);
    }
    headers::sections(pe, bytes, sections_out);
    imports::imports(pe, values, metrics, symbols_out);
    let signals = api_hash::native_resolver_signals(pe, bytes, values, metrics);
    exports::exports(pe, bytes, values, metrics, symbols_out);
    resources::extract(pe, bytes, values, metrics, errors_out);
    if let Some(ref dbg) = pe.debug_data {
        debug::extract(dbg, values, metrics, errors_out);
    }
    imports::bound_imports(pe, bytes, values, metrics);
    imports::delay_imports(pe, bytes, values, metrics, symbols_out);
    relocations::base_relocations(pe, bytes, values, metrics);
    load_config::tls_callbacks(pe, values, metrics);
    load_config::load_config(pe, bytes, values, metrics);
    anomalies::inflated_sections(pe, values);
    anomalies::entry_and_overlay(pe, bytes, values, metrics);
    anomalies::section_anomalies(pe, bytes, values, metrics);
    anomalies::dos_stub_anomalies(pe, bytes, metrics);
    anomalies::checksum(pe, bytes, metrics);
    clr::extract(pe, bytes, values, metrics, symbols_out);
    headers::data_directories(pe, values);
    anomalies::data_directory_anomalies(pe, bytes, values, metrics);
    if let Some(ref opt) = pe.header.optional_header {
        signature::extract(Some(pe), opt, bytes, values, metrics);
    }
    rich::extract(bytes, values);
    super::upx::detect(bytes, values);
    let go_sections = super::go_buildinfo::GoSections {
        buildinfo: super::go_buildinfo::pe_region(pe, bytes),
        buildid_note: None,
        pclntab: layout::section_bytes(pe, bytes, ".gopclntab"),
        rodata: layout::section_bytes(pe, bytes, ".rdata"),
    };
    let has_go_pclntab = go_sections
        .pclntab
        .is_some_and(super::go_buildinfo::has_pclntab_magic);
    super::go_buildinfo::detect(bytes, values, value_key!("pe.go"), None, &go_sections);
    // A Go PE may fold `.gopclntab` into `.rdata` and omit a literal
    // `.gopclntab` section. Build-info is still authoritative Go evidence, and
    // in that layout the native parser supplies the function inventory binform
    // would otherwise recover.
    let has_go_function_metadata = has_go_pclntab || values.get_key(value_key!("pe.go")).is_some();
    if has_go_function_metadata {
        go_functions(pe, &go_sections, has_go_pclntab, symbols_out);
    }
    super::build_toolchain::from_pe_rich(values);
    let Some(recovered) = native(bytes, symbols_out) else {
        return;
    };
    // A compact PE with no imports is often a resolver stub: correlate its
    // calls with the API-hash walkers the native scan found.
    let importless = api_hash::is_importless(bytes, symbols_out);
    if importless {
        api_hash::recover_api_hash_requests(
            pe,
            bytes,
            &signals,
            values,
            metrics,
            &recovered.functions,
        );
    }
    let counts = apply_native(recovered, symbols_out, Some(sections_out), metrics);
    if importless {
        metrics.insert(metric!("pe.importless_analysis"), 1.0);
        if counts.functions > 0 {
            metrics.insert(
                metric!("pe.importless_function_count"),
                f64::from(counts.functions),
            );
        }
    }
    recovered_counts(counts, metrics);
}

/// Add the functions a Go PE's pclntab names (see [`super::go_pclntab`]),
/// which then spare it binform's recovery. The table is the `.gopclntab`
/// section when there is one; Go's linker otherwise folds it into `.rdata`,
/// where a candidate must pass the same validation to count.
fn go_functions(
    pe: &goblin::pe::PE<'_>,
    go_sections: &super::go_buildinfo::GoSections<'_>,
    has_go_pclntab: bool,
    symbols_out: &mut crate::Symbols,
) {
    use goblin::pe::section_table::{IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE};
    let va = |rva: u32| pe.image_base.saturating_add(u64::from(rva));
    let Some(text) = pe
        .sections
        .iter()
        .find(|s| s.name().is_ok_and(|name| name == ".text"))
        .map(|s| va(s.virtual_address))
    else {
        return;
    };
    let Some(code) = super::go_pclntab::Code::of(
        pe.sections
            .iter()
            .filter(|s| s.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) != 0)
            .map(|s| {
                (
                    va(s.virtual_address),
                    u64::from(s.virtual_size.max(s.size_of_raw_data)),
                )
            }),
    ) else {
        return;
    };
    let functions = match (has_go_pclntab, go_sections.pclntab, go_sections.rodata) {
        (true, Some(table), _) => super::go_pclntab::functions(table, code, text),
        (_, _, Some(rdata)) => super::go_pclntab::find(rdata, code, text),
        _ => None,
    };
    for function in functions.into_iter().flatten() {
        symbols_out.push(function);
    }
}

/// The facts the headers alone support, for a PE goblin could not parse in
/// full. The header parse is far more tolerant: machine, subsystem,
/// characteristics and Authenticode survive a malformed or stripped import
/// directory (packed installers, Go binaries, obfuscated builds).
fn header_only(goblin_bytes: &[u8], bytes: &[u8], ctx: super::ExtractCtx<'_>) -> Result<(), Error> {
    let super::ExtractCtx {
        values,
        strings,
        metrics,
        sections: sections_out,
        symbols: symbols_out,
        errors: errors_out,
        ..
    } = ctx;
    // stng parses the bytes itself, tolerating the malformed structure.
    extract_binary_strings(bytes, strings, XorScan::Yes);
    let header = match goblin_safe::parse_pe_header(goblin_bytes) {
        goblin_safe::GoblinOutcome::Ok(header) => header,
        goblin_safe::GoblinOutcome::Failed(e) => {
            return Err(Error::malformed_caused_by("pe", e));
        }
        goblin_safe::GoblinOutcome::Panicked(msg) => {
            errors_out.record_panic(crate::Stage::PeParse, msg);
            return Ok(());
        }
    };
    headers::coff_header(&header.coff_header, values, metrics);
    headers::dos_header(&header, values);
    if let Some(ref opt) = header.optional_header {
        headers::optional_header(opt, values, metrics);
        // No section table, so no image hash: the signatures are reported,
        // and judged unverifiable.
        signature::extract(None, opt, bytes, values, metrics);
    }
    version_info::recover_partial(bytes, values);
    errors_out.record_fallback(crate::Stage::PeParse, "header-only fallback");
    metrics.insert(metric!("pe.partial_parse"), 1.0);
    anomalies::partial_section_overflows(bytes, &header, values, metrics);
    // goblin parsed no section table or import directory, so binform, which
    // reads a malformed or packed PE leniently, supplies them.
    if let Some(counts) = recover_natively(bytes, symbols_out, Some(sections_out), metrics) {
        recovered_counts(counts, metrics);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
