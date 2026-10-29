//! WebAssembly binary module (`\0asm`) structural extraction.
//!
//! WASM is a simple, well-specified container: a header followed by a sequence
//! of length-delimited sections. The high-signal behavioural facts live in the
//! **import** section (the host functions the module needs — its capability
//! surface, the WASM analogue of an ELF `.dynsym` / PE IAT) and the **export**
//! section (callable surface + toolchain fingerprint). rizin's `wasm` plugin
//! reads imports but drops the import *module* and returns no exports, so this
//! native walk parses the sections directly: complete, panic-free on hostile
//! input, and with no subprocess cost.
//!
//! Emitted facts:
//!   - `Symbol::Import { name, library }` per import (matchable via `type:
//!     import`) — `library` is the WASM module (`gojs`, `wasi_snapshot_preview1`).
//!   - `Symbol::Export { name }` per export.
//!   - `wasm.import_modules` / `wasm.imports` / `wasm.exports` value arrays.
//!   - `wasm.has_start`, `wasm.memory.initial` / `.max` value scalars.
//!   - `wasm.producers.*` from the `producers` custom section (toolchain).
//!   - `wasm.{import,export,section}_count` metrics.
//!
//! Capability interpretation (WASI `sock_*` ⇒ networking, `path_open` ⇒
//! filesystem, `gojs` ⇒ JS host bridge) is left to traits — this module only
//! records neutral structure.

use crate::metric;
use crate::output::{DiagnosticKind, Stage, Symbols, Values};
use crate::value_key;
use serde_json::Value as JsonValue;

mod xor;

/// Defensive caps so a malformed module with inflated section/vector counts
/// can't make us allocate unboundedly or spin. A real module stays far below.
const MAX_ENTRIES: usize = 8192;

/// Why a section body parse stopped short of its declared contents: the
/// kind to record and a message saying where.
type Bail = (DiagnosticKind, String);

fn malformed(message: String) -> Bail {
    (DiagnosticKind::Malformed, message)
}

/// Report a vector cut at [`MAX_ENTRIES`], once its kept entries are read.
fn check_cap(count: u64, what: &str) -> Result<(), Bail> {
    if count > MAX_ENTRIES as u64 {
        return Err((
            DiagnosticKind::Truncated,
            format!("{count} {what} declared; read the first {MAX_ENTRIES}"),
        ));
    }
    Ok(())
}

/// Cursor over the module bytes. Every read is bounds-checked and returns
/// `None` past the end, so a truncated or hostile module degrades to partial
/// facts instead of panicking.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn byte(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    /// Unsigned LEB128. Returns `None` on truncation or on a value wider than
    /// 64 bits (a malformed over-long encoding).
    fn uleb(&mut self) -> Option<u64> {
        super::common::read_uleb128(self.data, &mut self.pos)
    }

    /// A length-prefixed UTF-8 name (WASM `name` = `vec(byte)`). Lossily
    /// decoded so non-UTF-8 bytes can't abort extraction.
    fn name(&mut self) -> Option<String> {
        self.name_with_offset().map(|(name, _)| name)
    }

    /// Read a name and return the offset of its first UTF-8 byte relative to
    /// this reader's input. The length prefix is intentionally excluded so
    /// symbol evidence points at the name itself.
    fn name_with_offset(&mut self) -> Option<(String, usize)> {
        let len = crate::bytes::sat_usize(self.uleb()?);
        let offset = self.pos;
        let end = self.pos.checked_add(len)?;
        let slice = self.data.get(self.pos..end)?;
        self.pos = end;
        Some((String::from_utf8_lossy(slice).into_owned(), offset))
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        let end = self.pos.checked_add(n)?;
        if end > self.data.len() {
            return None;
        }
        self.pos = end;
        Some(())
    }
}

/// The distinct import module names, in first-seen order.
#[derive(Default)]
struct ImportModules {
    order: Vec<String>,
    seen: std::collections::HashSet<String>,
}

impl ImportModules {
    fn insert(&mut self, module: &str) {
        if !self.seen.contains(module) {
            self.seen.insert(module.to_owned());
            self.order.push(module.to_owned());
        }
    }
}

/// Read the import section: every import's module joins `modules`, and each
/// function import (external kind 0; 1 table, 2 memory and 3 global are
/// skipped past) becomes an `Import` symbol anchored at its field name.
fn extract_imports(
    body: &[u8],
    body_offset: u64,
    symbols_out: &mut Symbols,
    modules: &mut ImportModules,
    import_names: &mut Vec<String>,
) -> Result<(), Bail> {
    let mut r = Reader::new(body);
    let declared = r
        .uleb()
        .ok_or_else(|| malformed("import count truncated".into()))?;
    for i in 0..crate::bytes::sat_usize(declared).min(MAX_ENTRIES) {
        let truncated = || malformed(format!("import {i} truncated"));
        let (module, _module_offset) = r.name_with_offset().ok_or_else(truncated)?;
        let (field, field_offset) = r.name_with_offset().ok_or_else(truncated)?;
        let kind = r.byte().ok_or_else(truncated)?;
        // Skip the kind-specific descriptor so the next import aligns.
        let ok = match kind {
            0x00 => r.uleb().map(|_| ()),                       // func: typeidx
            0x01 => r.byte().and_then(|_| skip_limits(&mut r)), // table: reftype + limits
            0x02 => skip_limits(&mut r),                        // memory: limits
            0x03 => r.skip(2),                                  // global: valtype + mut
            _ => None,
        };
        modules.insert(&module);
        // Only function imports are callable host capabilities; record those
        // as Import symbols. Table/memory/global imports still count toward
        // the module list above.
        if kind == 0x00 {
            import_names.push(field.clone());
            symbols_out.push(crate::Symbol::Import {
                name: field,
                alias: None,
                library: Some(module),
                offset: Some(body_offset + field_offset as u64),
                ordinal: None,
            });
        }
        if ok.is_none() {
            return Err(malformed(format!(
                "import {i} has a malformed or unknown descriptor (kind {kind:#04x})"
            )));
        }
    }
    check_cap(declared, "imports")
}

fn skip_limits(r: &mut Reader<'_>) -> Option<()> {
    let flags = r.byte()?;
    r.uleb()?; // min
    if flags & 0x01 != 0 {
        r.uleb()?; // max
    }
    Some(())
}

fn extract_exports(
    body: &[u8],
    body_offset: u64,
    symbols_out: &mut Symbols,
    export_names: &mut Vec<String>,
) -> Result<(), Bail> {
    let mut r = Reader::new(body);
    let declared = r
        .uleb()
        .ok_or_else(|| malformed("export count truncated".into()))?;
    for i in 0..crate::bytes::sat_usize(declared).min(MAX_ENTRIES) {
        let truncated = || malformed(format!("export {i} truncated"));
        let (name, name_offset) = r.name_with_offset().ok_or_else(truncated)?;
        r.byte().ok_or_else(truncated)?; // export kind
        r.uleb().ok_or_else(truncated)?; // index
        export_names.push(name.clone());
        symbols_out.push(crate::Symbol::Export {
            name,
            offset: Some(body_offset + name_offset as u64),
            ordinal: None,
            forward_to: None,
        });
    }
    check_cap(declared, "exports")
}

/// Parse the first memory's declared page limits.
fn extract_memory(body: &[u8], values: &mut Values) {
    let mut r = Reader::new(body);
    let Some(count) = r.uleb() else { return };
    if count == 0 {
        return;
    }
    let Some(flags) = r.byte() else { return };
    let Some(min) = r.uleb() else { return };
    values.insert_key(value_key!("wasm.memory.initial"), JsonValue::from(min));
    if flags & 0x01 != 0
        && let Some(max) = r.uleb()
    {
        values.insert_key(value_key!("wasm.memory.max"), JsonValue::from(max));
    }
}

/// The `producers` custom section: a vec of `(field_name, vec(name, version))`.
/// Records the first value of each field under `wasm.producers.<field>`.
fn extract_producers(r: &mut Reader<'_>, values: &mut Values) {
    let Some(field_count) = r.uleb() else { return };
    let field_count = crate::bytes::sat_usize(field_count).min(64);
    for _ in 0..field_count {
        let Some(field) = r.name() else { return };
        let Some(vcount) = r.uleb() else { return };
        let vcount = crate::bytes::sat_usize(vcount).min(64);
        let mut first: Option<String> = None;
        for _ in 0..vcount {
            let Some(name) = r.name() else { return };
            let Some(version) = r.name() else { return };
            if first.is_none() {
                first = Some(if version.is_empty() {
                    name
                } else {
                    format!("{name} {version}")
                });
            }
        }
        if let Some(v) = first {
            values.insert_key_at(
                value_key!("wasm.producers"),
                &field.replace('-', "_"),
                JsonValue::String(v),
            );
        }
    }
}

pub(super) fn extract(bytes: &[u8], ctx: super::ExtractCtx<'_>) {
    let super::ExtractCtx {
        values,
        strings,
        metrics,
        symbols: symbols_out,
        errors: errors_out,
        ..
    } = ctx;
    // Header: `\0asm` + u32 version. Detection already vetted this, but guard
    // anyway so a forced/misrouted file can't index out of range.
    if bytes.len() < 8 || !bytes.starts_with(b"\0asm") {
        tracing::debug!(
            target: "filefacts::wasm",
            stage = "header",
            len = bytes.len(),
            "no WebAssembly header; skipped"
        );
        return;
    }

    // Bytecode is executable code too: recover only instruction-bound XOR
    // loops over active data. No guest module or imported API is executed.
    super::common::extract_binary_strings(bytes, strings, super::common::XorScan::No);
    let decoded = xor::recover(bytes);
    if !decoded.is_empty() {
        metrics.insert(
            metric!("wasm.xor_decoded_range_count"),
            decoded.len() as f64,
        );
        metrics.insert(
            metric!("wasm.xor_decoded_bytes"),
            decoded.iter().map(|r| r.bytes.len()).sum::<usize>() as f64,
        );
        values.insert_key(
            value_key!("wasm.xor_decode"),
            serde_json::json!({
                "range_count": decoded.len(),
                "decoded_bytes": decoded.iter().map(|r| r.bytes.len()).sum::<usize>(),
            }),
        );
        let options = stng::ExtractOptions::new(4)
            .with_garbage_filter(true)
            .with_caller_provides_symbols(true);
        let mut rows = Vec::new();
        for range in decoded {
            for mut row in stng::extract_strings_with_options(&range.bytes, &options) {
                row.data_offset = row.data_offset.saturating_add(range.offset as u64);
                row.method = stng::StringMethod::XorDecode;
                rows.push(row);
            }
        }
        strings.text.append_rows(&rows);
    }

    let mut r = Reader::new(bytes);
    r.pos = 8;

    let mut modules = ImportModules::default();
    let mut import_names: Vec<String> = Vec::new();
    let mut export_names: Vec<String> = Vec::new();
    let mut has_start = false;
    let mut section_count: u64 = 0;
    // Known section ids already read. The spec allows each non-custom section
    // at most once, and honouring that is what makes MAX_ENTRIES a bound on
    // the whole module rather than on each of any number of import sections.
    let mut seen_ids: u64 = 0;

    while let Some(id) = r.byte() {
        let header_at = r.pos - 1;
        // A section whose header or body runs past the end of the file ends
        // the walk; everything after it is unread, so say so.
        let Some(body) = r.uleb().and_then(|size| {
            let start = r.pos;
            bytes.get(start..start.checked_add(usize::try_from(size).ok()?)?)
        }) else {
            errors_out.record(
                DiagnosticKind::Truncated,
                Stage::WasmParse,
                format!("wasm section {id} at offset {header_at} runs past the end of the file"),
            );
            break;
        };
        let start = r.pos;
        let end = start + body.len();
        section_count += 1;

        let id_bit = 1u64.checked_shl(u32::from(id)).unwrap_or(0);
        if id != 0 && seen_ids & id_bit != 0 {
            errors_out.record(
                DiagnosticKind::Malformed,
                Stage::WasmParse,
                format!("wasm section {id} at offset {header_at} repeats; only the first is read"),
            );
            r.pos = end;
            continue;
        }
        seen_ids |= id_bit;

        let parsed = match id {
            2 => extract_imports(
                body,
                start as u64,
                symbols_out,
                &mut modules,
                &mut import_names,
            )
            .map_err(|(kind, why)| (kind, format!("import section: {why}"))),
            7 => extract_exports(body, start as u64, symbols_out, &mut export_names)
                .map_err(|(kind, why)| (kind, format!("export section: {why}"))),
            8 => {
                has_start = true;
                Ok(())
            }
            5 => {
                extract_memory(body, values);
                Ok(())
            }
            0 => {
                // Custom section: a name followed by payload. `producers`
                // carries the toolchain; others are ignored here (strings
                // still surface their bytes via the generic text scan).
                let mut cr = Reader::new(body);
                if let Some(name) = cr.name()
                    && name == "producers"
                {
                    extract_producers(&mut cr, values);
                }
                Ok(())
            }
            _ => Ok(()),
        };
        if let Err((kind, message)) = parsed {
            errors_out.record(kind, Stage::WasmParse, format!("wasm {message}"));
        }

        // Advance to the next section regardless of how far the body parse
        // got — section sizes are authoritative.
        r.pos = end;
    }

    values.insert_key(value_key!("wasm.has_start"), JsonValue::Bool(has_start));
    if !modules.order.is_empty() {
        values.insert_key(
            value_key!("wasm.import_modules"),
            JsonValue::from(modules.order),
        );
    }
    import_names.truncate(MAX_ENTRIES);
    export_names.truncate(MAX_ENTRIES);
    metrics.insert(metric!("wasm.import_count"), import_names.len() as f64);
    metrics.insert(metric!("wasm.export_count"), export_names.len() as f64);
    metrics.insert(metric!("wasm.section_count"), section_count as f64);
    if !import_names.is_empty() {
        values.insert_key(value_key!("wasm.imports"), JsonValue::from(import_names));
    }
    if !export_names.is_empty() {
        values.insert_key(value_key!("wasm.exports"), JsonValue::from(export_names));
    }
}

#[cfg(test)]
mod tests;
