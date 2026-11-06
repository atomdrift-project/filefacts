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
use crate::value_key;

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
    /// Runtime symbol prefixes (leading underscores stripped) and the
    /// instrumentation each one names.
    const PREFIXES: &[(&str, &str)] = &[
        ("asan_", "asan"),
        ("tsan_", "tsan"),
        ("msan_", "msan"),
        ("ubsan_", "ubsan"),
        ("hwasan_", "hwasan"),
        ("lsan_", "lsan"),
        ("kasan_", "kasan"),
        ("llvm_profile_", "pgo"),
        ("llvm_coverage_", "coverage"),
        ("llvm_covmap_", "coverage"),
        ("gcov_", "gcov"),
        ("llvm_gcov_", "gcov"),
    ];
    let out: BTreeSet<&str> = each_import_name(symbols)
        .filter_map(|name| {
            let s = name.trim_start_matches('_');
            PREFIXES
                .iter()
                .find(|(prefix, _)| s.starts_with(prefix))
                .map(|&(_, tag)| tag)
        })
        .collect();
    if out.is_empty() {
        return;
    }
    values.insert_key(
        value_key!("binary.sanitizers"),
        JsonValue::Array(out.into_iter().map(JsonValue::from).collect()),
    );
}

fn fortify(symbols: &Symbols, values: &mut Values) {
    let mut out: BTreeSet<&str> = BTreeSet::new();
    for name in each_import_name(symbols) {
        let s = name.trim_start_matches('_');
        let Some(base) = s.strip_suffix("_chk") else {
            continue;
        };
        // Filter sanitizer families that happen to end in `_chk`.
        if base.is_empty() || base.starts_with("asan") || base.starts_with("tsan") {
            continue;
        }
        out.insert(base);
    }
    if out.is_empty() {
        return;
    }
    values.insert_key(
        value_key!("binary.fortify"),
        JsonValue::Array(out.into_iter().map(JsonValue::from).collect()),
    );
}
