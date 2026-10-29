use super::*;
use crate::output::Errors;

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
    let mut out = crate::formats::Sinks::default();
    extract(bytes, out.ctx());
    (out.values, out.errors)
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
    assert_eq!(entry.kind, DiagnosticKind::Malformed);
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
    assert_eq!(entry.kind, DiagnosticKind::Truncated);
    assert!(entry.message.contains("section 2"), "{entry:?}");
}

/// A repeated import section is reported and skipped, so `MAX_ENTRIES`
/// bounds the module's imports however many import sections it repeats;
/// module names stay deduplicated in first-seen order.
#[test]
fn repeated_import_section_is_recorded_and_not_reread() {
    let mut imports = vec![3];
    imports.extend_from_slice(IMPORT_ENV_F);
    imports.extend_from_slice(b"\x04wasi\x01g\x00\x00");
    imports.extend_from_slice(IMPORT_ENV_F);
    let second = b"\x01\x05other\x01h\x00\x00";
    let (v, errors) = run(&module(&[(2, &imports), (2, second), (2, second)]));
    assert_eq!(
        v.get("wasm.import_modules"),
        Some(&serde_json::json!(["env", "wasi"]))
    );
    assert_eq!(
        v.get("wasm.imports"),
        Some(&serde_json::json!(["f", "g", "f"]))
    );
    assert_eq!(errors.len(), 2, "{errors:?}");
    let entry = errors.iter().next().expect("repeat recorded");
    assert_eq!(entry.kind, DiagnosticKind::Malformed);
    assert!(entry.message.contains("section 2"), "{entry:?}");
    assert!(entry.message.contains("repeats"), "{entry:?}");
}
