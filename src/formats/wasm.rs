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
use crate::output::{ErrorKind, Errors, Metrics, Section, Stage, Strings, Symbols, Values};
use crate::value_key;
use serde_json::Value as JsonValue;

/// Defensive caps so a malformed module with inflated section/vector counts
/// can't make us allocate unboundedly or spin. A real module stays far below.
const MAX_ENTRIES: usize = 8192;

/// Why a section body parse stopped short of its declared contents: the
/// kind to record and a message saying where.
type Bail = (ErrorKind, String);

fn malformed(message: String) -> Bail {
    (ErrorKind::Malformed, message)
}

/// Report a vector cut at [`MAX_ENTRIES`], once its kept entries are read.
fn check_cap(count: u64, what: &str) -> Result<(), Bail> {
    if count > MAX_ENTRIES as u64 {
        return Err((
            ErrorKind::Truncated,
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
) -> Result<(), Bail> {
    let mut r = Reader::new(body);
    let declared = r
        .uleb()
        .ok_or_else(|| malformed("import count truncated".into()))?;
    for i in 0..(declared as usize).min(MAX_ENTRIES) {
        let truncated = || malformed(format!("import {i} truncated"));
        let (module, _module_offset) = r.name_with_offset().ok_or_else(truncated)?;
        let (field, field_offset) = r.name_with_offset().ok_or_else(truncated)?;
        let kind = r.byte().ok_or_else(truncated)?;
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

fn skip_table_type(r: &mut Reader<'_>) -> Option<()> {
    r.byte()?; // element reftype
    skip_limits(r)
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
    for i in 0..(declared as usize).min(MAX_ENTRIES) {
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
            values.insert_key_at(
                value_key!("wasm.producers"),
                &field.replace('-', "_"),
                JsonValue::String(v),
            );
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
    errors_out: &mut Errors,
) -> Result<(), Error> {
    // Header: `\0asm` + u32 version. Detection already vetted this, but guard
    // anyway so a forced/misrouted file can't index out of range.
    if bytes.len() < 8 || !bytes.starts_with(b"\0asm") {
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
        let header_at = r.pos - 1;
        // A section whose header or body runs past the end of the file ends
        // the walk; everything after it is unread, so say so.
        let Some(body) = r.uleb().and_then(|size| {
            let start = r.pos;
            bytes.get(start..start.checked_add(usize::try_from(size).ok()?)?)
        }) else {
            errors_out.record(
                ErrorKind::Truncated,
                Stage::WasmParse,
                format!("wasm section {id} at offset {header_at} runs past the end of the file"),
            );
            break;
        };
        let start = r.pos;
        let end = start + body.len();
        section_count += 1;

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
    if !modules.is_empty() {
        values.insert_key(value_key!("wasm.import_modules"), JsonValue::from(modules));
    }
    if !import_names.is_empty() {
        import_names.truncate(MAX_ENTRIES);
        values.insert_key(
            value_key!("wasm.imports"),
            JsonValue::from(import_names.clone()),
        );
    }
    if !export_names.is_empty() {
        export_names.truncate(MAX_ENTRIES);
        values.insert_key(
            value_key!("wasm.exports"),
            JsonValue::from(export_names.clone()),
        );
    }

    metrics.insert(metric!("wasm.import_count"), import_names.len() as f64);
    metrics.insert(metric!("wasm.export_count"), export_names.len() as f64);
    metrics.insert(metric!("wasm.section_count"), section_count as f64);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(sections: &[(u8, &[u8])]) -> Vec<u8> {
        let mut out = b"\0asm\x01\0\0\0".to_vec();
        for (id, body) in sections {
            out.push(*id);
            out.push(body.len() as u8); // single-byte LEB128 for test sizes
            out.extend_from_slice(body);
        }
        out
    }

    fn run(bytes: &[u8]) -> (Values, Errors) {
        let mut v = Values::new();
        let mut errors = Errors::new();
        extract(
            bytes,
            &mut v,
            &mut Strings::default(),
            &mut Metrics::new(),
            &mut Vec::new(),
            &mut Symbols::default(),
            &mut errors,
        )
        .unwrap();
        (v, errors)
    }

    /// `env.f`, a function import of type 0.
    const IMPORT_ENV_F: &[u8] = b"\x03env\x01f\x00\x00";

    #[test]
    fn well_formed_module_records_no_errors() {
        let mut imports = vec![1];
        imports.extend_from_slice(IMPORT_ENV_F);
        let exports = b"\x01\x04main\x00\x00";
        let (v, errors) = run(&module(&[(2, &imports), (7, exports)]));
        assert_eq!(v.get("wasm.imports"), Some(&serde_json::json!(["f"])));
        assert_eq!(v.get("wasm.exports"), Some(&serde_json::json!(["main"])));
        assert!(errors.is_empty(), "{errors:?}");
    }

    /// The import vector stops at a broken entry. What was read is kept, and
    /// the stop is recorded instead of passing as a complete import list.
    #[test]
    fn malformed_import_is_recorded_and_earlier_imports_kept() {
        let mut imports = vec![2];
        imports.extend_from_slice(IMPORT_ENV_F);
        imports.extend_from_slice(b"\x03env");
        let (v, errors) = run(&module(&[(2, &imports)]));
        assert_eq!(v.get("wasm.imports"), Some(&serde_json::json!(["f"])));
        let entry = errors.iter().next().expect("bail recorded");
        assert_eq!(entry.kind, ErrorKind::Malformed);
        assert_eq!(entry.stage, Stage::WasmParse);
        assert!(entry.message.contains("import 1 truncated"), "{entry:?}");
    }

    #[test]
    fn section_past_end_of_file_is_recorded() {
        let mut bytes = module(&[(7, b"\x00")]);
        bytes.extend_from_slice(&[2, 100, 1, 2, 3]);
        let (v, errors) = run(&bytes);
        assert_eq!(v.get("wasm.has_start"), Some(&serde_json::json!(false)));
        let entry = errors.iter().next().expect("truncation recorded");
        assert_eq!(entry.kind, ErrorKind::Truncated);
        assert!(entry.message.contains("section 2"), "{entry:?}");
    }
}

// rebuild-marker
