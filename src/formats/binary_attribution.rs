//! Cross-format binary attribution derived from the import-symbol view:
//! sanitizer instrumentation and `_FORTIFY_SOURCE` wrappers.
//!
//! Both are format-agnostic — the compiler links the runtime as
//! ordinary imports on whatever platform you target — so they live
//! outside the per-format extractors and run once over the merged
//! [`crate::Symbols`] view.
//!
//! Emits:
//! - `binary.sanitizers[]` — sorted unique names: `asan`, `tsan`,
//!   `msan`, `ubsan`, `hwasan`, `lsan`, `kasan`, `pgo`, `coverage`,
//!   `gcov`. Presence usually means a debug build that leaked to
//!   production — strong attribution / mistake signal.
//! - `binary.fortify[]` — the libc base names whose `_chk` wrapper
//!   the binary calls (e.g. `["memcpy", "sprintf", "strcpy"]`).

use std::collections::BTreeSet;

use serde_json::Value as JsonValue;

use crate::output::{Symbol, SymbolKind, Symbols, Values};

pub(super) fn emit(symbols: &Symbols, values: &mut Values) {
    sanitizers(symbols, values);
    fortify(symbols, values);
}

fn each_import_name(symbols: &Symbols) -> impl Iterator<Item = &str> {
    symbols
        .iter_kind(SymbolKind::Import)
        .filter_map(|s| match s {
            Symbol::Import { name, .. } => Some(name.as_str()),
            _ => None,
        })
}

fn sanitizers(symbols: &Symbols, values: &mut Values) {
    let mut out: BTreeSet<&'static str> = BTreeSet::new();
    for name in each_import_name(symbols) {
        let s = name.trim_start_matches('_');
        let tag = if s.starts_with("asan_") {
            "asan"
        } else if s.starts_with("tsan_") {
            "tsan"
        } else if s.starts_with("msan_") {
            "msan"
        } else if s.starts_with("ubsan_") {
            "ubsan"
        } else if s.starts_with("hwasan_") {
            "hwasan"
        } else if s.starts_with("lsan_") {
            "lsan"
        } else if s.starts_with("kasan_") {
            "kasan"
        } else if s.starts_with("llvm_profile_") {
            "pgo"
        } else if s.starts_with("llvm_coverage_") || s.starts_with("llvm_covmap_") {
            "coverage"
        } else if s.starts_with("gcov_") || s.starts_with("llvm_gcov_") {
            "gcov"
        } else {
            continue;
        };
        out.insert(tag);
    }
    if out.is_empty() {
        return;
    }
    values.insert(
        "binary.sanitizers",
        JsonValue::Array(
            out.into_iter()
                .map(|s| JsonValue::String(s.into()))
                .collect(),
        ),
    );
}

fn fortify(symbols: &Symbols, values: &mut Values) {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for name in each_import_name(symbols) {
        let s = name.trim_start_matches('_');
        let Some(base) = s.strip_suffix("_chk") else {
            continue;
        };
        // Filter sanitizer families that happen to end in `_chk`.
        if base.is_empty() || base.starts_with("asan") || base.starts_with("tsan") {
            continue;
        }
        out.insert(base.to_string());
    }
    if out.is_empty() {
        return;
    }
    values.insert(
        "binary.fortify",
        JsonValue::Array(out.into_iter().map(JsonValue::String).collect()),
    );
}
