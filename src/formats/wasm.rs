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

use crate::error::Error;
use crate::metric;
use crate::output::{Errors, Metrics, Section, Strings, Symbols, Values};
use serde_json::Value as JsonValue;

/// Defensive caps so a malformed module with inflated section/vector counts
/// can't make us allocate unboundedly or spin. A real module stays far below.
const MAX_ENTRIES: usize = 8192;

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
        let mut result: u64 = 0;
        let mut shift = 0u32;
        loop {
            let b = self.byte()?;
            if shift >= 64 {
                return None;
            }
            result |= u64::from(b & 0x7f).checked_shl(shift)?;
            if b & 0x80 == 0 {
                return Some(result);
            }
            shift += 7;
        }
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
        let len = self.uleb()? as usize;
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

/// External-kind byte → (kind label, has_extra_index/limits descriptor).
/// 0 func, 1 table, 2 memory, 3 global.
fn extract_imports(
    body: &[u8],
    body_offset: u64,
    symbols_out: &mut Symbols,
    modules: &mut Vec<String>,
    import_names: &mut Vec<String>,
) {
    let mut r = Reader::new(body);
    let Some(count) = r.uleb() else { return };
    let count = (count as usize).min(MAX_ENTRIES);
    for _ in 0..count {
        let Some((module, _module_offset)) = r.name_with_offset() else {
            return;
        };
        let Some((field, field_offset)) = r.name_with_offset() else {
            return;
        };
        let Some(kind) = r.byte() else { return };
        // Skip the kind-specific descriptor so the next import aligns.
        let ok = match kind {
            0x00 => r.uleb().map(|_| ()),    // func: typeidx
            0x01 => skip_table_type(&mut r), // table: reftype + limits
            0x02 => skip_limits(&mut r),     // memory: limits
            0x03 => r.skip(2),               // global: valtype + mut
            _ => None,
        };
        if !modules.contains(&module) {
            modules.push(module.clone());
        }
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
            return;
        }
    }
}

fn skip_limits(r: &mut Reader<'_>) -> Option<()> {
    let flags = r.byte()?;
    r.uleb()?; // min
    if flags & 0x01 != 0 {
        r.uleb()?; // max
    }
    Some(())
}

fn skip_table_type(r: &mut Reader<'_>) -> Option<()> {
    r.byte()?; // element reftype
    skip_limits(r)
}

fn extract_exports(
    body: &[u8],
    body_offset: u64,
    symbols_out: &mut Symbols,
    export_names: &mut Vec<String>,
) {
    let mut r = Reader::new(body);
    let Some(count) = r.uleb() else { return };
    let count = (count as usize).min(MAX_ENTRIES);
    for _ in 0..count {
        let Some((name, name_offset)) = r.name_with_offset() else {
            return;
        };
        if r.byte().is_none() {
            return;
        } // export kind
        if r.uleb().is_none() {
            return;
        } // index
        export_names.push(name.clone());
        symbols_out.push(crate::Symbol::Export {
            name,
            offset: Some(body_offset + name_offset as u64),
            ordinal: None,
            forward_to: None,
        });
    }
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
    values.insert("wasm.memory.initial", JsonValue::from(min));
    if flags & 0x01 != 0
        && let Some(max) = r.uleb()
    {
        values.insert("wasm.memory.max", JsonValue::from(max));
    }
}

/// The `producers` custom section: a vec of `(field_name, vec(name, version))`.
/// Records the first value of each field under `wasm.producers.<field>`.
fn extract_producers(r: &mut Reader<'_>, values: &mut Values) {
    let Some(field_count) = r.uleb() else { return };
    let field_count = (field_count as usize).min(64);
    for _ in 0..field_count {
        let Some(field) = r.name() else { return };
        let Some(vcount) = r.uleb() else { return };
        let vcount = (vcount as usize).min(64);
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
            let key = format!("wasm.producers.{}", field.replace('-', "_"));
            values.insert(&key, JsonValue::String(v));
        }
    }
}

pub(super) fn extract(
    bytes: &[u8],
    values: &mut Values,
    _strings: &mut Strings,
    metrics: &mut Metrics,
    _sections_out: &mut Vec<Section>,
    symbols_out: &mut Symbols,
    _errors_out: &mut Errors,
) -> Result<(), Error> {
    // Header: `\0asm` + u32 version. Detection already vetted this, but guard
    // anyway so a forced/misrouted file can't index out of range.
    if bytes.len() < 8 || &bytes[0..4] != b"\0asm" {
        return Ok(());
    }

    let mut r = Reader::new(bytes);
    r.pos = 8;

    let mut modules: Vec<String> = Vec::new();
    let mut import_names: Vec<String> = Vec::new();
    let mut export_names: Vec<String> = Vec::new();
    let mut has_start = false;
    let mut section_count: u64 = 0;

    while let Some(id) = r.byte() {
        let Some(size) = r.uleb() else { break };
        let size = size as usize;
        let start = r.pos;
        let Some(end) = start.checked_add(size) else {
            break;
        };
        let Some(body) = bytes.get(start..end) else {
            break;
        };
        section_count += 1;

        match id {
            2 => extract_imports(
                body,
                start as u64,
                symbols_out,
                &mut modules,
                &mut import_names,
            ),
            7 => extract_exports(body, start as u64, symbols_out, &mut export_names),
            8 => has_start = true,
            5 => extract_memory(body, values),
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
            }
            _ => {}
        }

        // Advance to the next section regardless of how far the body parse
        // got — section sizes are authoritative.
        r.pos = end;
    }

    values.insert("wasm.has_start", JsonValue::Bool(has_start));
    if !modules.is_empty() {
        values.insert("wasm.import_modules", JsonValue::from(modules));
    }
    if !import_names.is_empty() {
        import_names.truncate(MAX_ENTRIES);
        values.insert("wasm.imports", JsonValue::from(import_names.clone()));
    }
    if !export_names.is_empty() {
        export_names.truncate(MAX_ENTRIES);
        values.insert("wasm.exports", JsonValue::from(export_names.clone()));
    }

    metrics.insert(metric!("wasm.import_count"), import_names.len() as f64);
    metrics.insert(metric!("wasm.export_count"), export_names.len() as f64);
    metrics.insert(metric!("wasm.section_count"), section_count as f64);

    Ok(())
}

// rebuild-marker
