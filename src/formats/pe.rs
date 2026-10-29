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
mod imports;
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
use goblin::pe::optional_header::OptionalHeader;

use crate::error::Error;
use crate::formats::common::{
    NativeFormat, RizinTarget, XorScan, extract_binary_strings, extract_binary_strings_from_object,
    rizin_fallback_with_sections,
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
        ref rizin,
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
    let native = api_hash::native_resolver_signals(pe, bytes, values, metrics);
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
    // `.gopclntab` section. Build-info is still authoritative Go
    // evidence, and in that layout the native parser supplies no typed
    // function inventory for the Rizin fallback to skip over.
    let has_go_function_metadata = has_go_pclntab || values.get_key(value_key!("pe.go")).is_some();
    super::build_toolchain::from_pe_rich(values);
    let target = RizinTarget {
        format: NativeFormat::Pe,
        bytes,
        strings,
        go_function_metadata: has_go_function_metadata,
        settings: rizin,
    };
    api_hash::rizin_importless_analysis(
        pe,
        target,
        &native,
        values,
        sections_out,
        symbols_out,
        metrics,
    );
    rizin_fallback_with_sections(
        target,
        declares_export_directory(pe.header.optional_header.as_ref()),
        symbols_out,
        sections_out,
        metrics,
    );
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
        ref rizin,
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
    // goblin parsed no section table or import directory, so the section and
    // symbol views are empty: the case rizin recovery exists for, since a
    // malformed or packed PE that rizin parses fine would otherwise surface
    // zero sections and imports.
    rizin_fallback_with_sections(
        RizinTarget {
            format: NativeFormat::Pe,
            bytes,
            strings,
            go_function_metadata: false,
            settings: rizin,
        },
        declares_export_directory(header.optional_header.as_ref()),
        symbols_out,
        sections_out,
        metrics,
    );
    Ok(())
}

/// Whether the optional header points at an export directory. Without one
/// the loader resolves no exports, so any a disassembler recovers are other
/// global symbols (Go's `gopclntab`) and must not reach the export view.
/// Unset and zeroed slots both mean absent, as in `pe.data_directories`.
fn declares_export_directory(opt: Option<&OptionalHeader>) -> bool {
    opt.and_then(|opt| opt.data_directories.get_export_table())
        .is_some_and(|dir| dir.virtual_address != 0 || dir.size != 0)
}

#[cfg(test)]
mod tests;
