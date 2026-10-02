//! Metrics derived from what the format extractors recorded, rather than
//! from any one format: section aggregates, cross-format `binary.*` string
//! and layout statistics, overlay detection and per-kind symbol counts.

use crate::metric;
use crate::output::{self, Metrics, SectionFlag, Sections, Span, SpanBuilder, SymbolKind, Symbols};
use crate::scan;

/// Whether an exported symbol represents a callable/public API rather than a
/// compiler or loader artifact.
///
/// Itanium-ABI RTTI (`_ZTI*` typeinfo, `_ZTS*` typename, `_ZTV*` vtable,
/// `_ZTT*` VTT) is emitted by the C++ compiler for any type used with
/// exceptions or `dynamic_cast`; `mh_execute_header` is the Mach-O image
/// header every executable exports. Neither says a caller can do anything
/// with this binary.
fn is_api_export(name: &str) -> bool {
    let bare = name.trim_start_matches('_');
    if bare == "mh_execute_header" {
        return false;
    }
    !(bare.starts_with("ZTI")
        || bare.starts_with("ZTS")
        || bare.starts_with("ZTV")
        || bare.starts_with("ZTT"))
}

/// Emit `imports.count`, `exports.count`, `exports.api_count`,
/// `functions.count`, and `binds.count` (calls/members are covered by the
/// byte-identical `ast.call_count`/`ast.member_count`; identifier
/// occurrence counts come from `identifier_metrics` —
/// `identifiers.count`/`identifiers.unique`) for whichever kinds have at
/// least one entry.
pub(crate) fn emit_symbol_kind_counts(symbols: &Symbols, metrics: &mut Metrics) {
    let mut imports = 0u64;
    let mut exports = 0u64;
    let mut api_exports = 0u64;
    let mut functions = 0u64;
    let mut binds = 0u64;
    for s in symbols {
        match s.kind() {
            SymbolKind::Import => imports += 1,
            SymbolKind::Export => {
                exports += 1;
                if is_api_export(s.name().unwrap_or_default()) {
                    api_exports += 1;
                }
            }
            SymbolKind::Function => functions += 1,
            SymbolKind::Bind => binds += 1,
            SymbolKind::Call | SymbolKind::Member | SymbolKind::Identifier => {}
        }
    }
    if imports > 0 {
        metrics.insert(metric!("imports.count"), imports as f64);
    }
    if exports > 0 {
        metrics.insert(metric!("exports.count"), exports as f64);
        // Exports minus the ones the toolchain emits on its own. A rule that
        // reads "this has a real public API, so treat it as a library" must not
        // be satisfied by artifacts: any C++ binary built with exceptions
        // exports typeinfo and typename symbols whether or not it exports
        // anything a caller could use, and a Mach-O executable always exports
        // `mh_execute_header`. An obfuscated stub with zero real exports
        // reaches four on artifacts alone, which is enough to trip an
        // `exports.count >= 4` suppression and silence the rules that would
        // have described it.
        metrics.insert(metric!("exports.api_count"), api_exports as f64);
    }
    if functions > 0 {
        metrics.insert(metric!("functions.count"), functions as f64);
    }
    if binds > 0 {
        metrics.insert(metric!("binds.count"), binds as f64);
    }
}

/// Heuristic: "looks like a natural-language sentence" — short enough
/// to be ML-cheap, long enough to filter out short tokens. A binary
/// embedding many of these usually contains documentation strings,
/// error messages, or string-table assets — a different population
/// than a binary whose strings are all `__cxx_…` symbols or paths.
fn is_sentence_like(text: &str) -> bool {
    if text.len() < 12 {
        return false;
    }
    let mut spaces = 0_usize;
    for b in text.bytes() {
        if b == b' ' {
            spaces += 1;
        }
    }
    if spaces < 2 {
        return false;
    }
    let mut alpha_tokens = 0_usize;
    let mut tokens = 0_usize;
    for tok in text.split_whitespace() {
        tokens += 1;
        if tok.chars().filter(|c| c.is_alphabetic()).count() >= 2 {
            alpha_tokens += 1;
        }
    }
    tokens >= 3 && alpha_tokens >= 2
}

pub(crate) fn emit_section_metrics(sections: &Sections, metrics: &mut Metrics) {
    metrics.insert(metric!("sections.count"), sections.len() as f64);

    // Per-section entropies live on `Section.entropy`. Aggregate
    // max / mean across the sections that have file-backed bytes (the
    // `None` entries are SHT_NOBITS / BSS-style purely-virtual regions
    // and shouldn't pull the mean toward zero).
    let mut entropy_max = 0.0_f64;
    let mut max_span: Option<Span> = None;
    let mut entropy_sum = 0.0_f64;
    let mut entropy_n = 0_u64;
    for s in sections {
        if let Some(e) = s.entropy {
            if max_span.is_none() || e > entropy_max {
                entropy_max = e;
                max_span = Some(Span::new(s.file_offset, s.file_size));
            }
            entropy_sum += e;
            entropy_n += 1;
        }
    }
    if entropy_n > 0 {
        // Locate the peak-entropy section so a packer/encrypted-section finding
        // can point at it; the mean has no single location.
        match max_span {
            Some(span) => {
                metrics.insert_located(metric!("sections.max_entropy"), entropy_max, [span])
            }
            None => metrics.insert(metric!("sections.max_entropy"), entropy_max),
        }
        metrics.insert(
            metric!("sections.avg_entropy"),
            entropy_sum / entropy_n as f64,
        );
    }

    let mut executable = 0_u64;
    let mut writable = 0_u64;
    let mut wx = 0_u64;
    let mut code_size: u64 = 0;
    let mut nonstandard = 0_u64;
    let mut concatenated_names: Vec<u8> = Vec::new();
    for s in sections {
        let is_exec = s.is_executable();
        let is_write = s.is_writable();
        if is_exec {
            executable += 1;
            code_size = code_size.saturating_add(s.file_size);
        }
        if is_write {
            writable += 1;
        }
        if is_exec && is_write {
            wx += 1;
        }
        if !is_well_known_section_name(&s.name) {
            nonstandard += 1;
        }
        concatenated_names.extend_from_slice(s.name.as_bytes());
    }
    metrics.insert(metric!("sections.executable_count"), executable as f64);
    metrics.insert(metric!("sections.writable_count"), writable as f64);
    metrics.insert(metric!("sections.executable_writable_count"), wx as f64);
    if code_size > 0 {
        metrics.insert(metric!("sections.code_size"), code_size as f64);
    }
    metrics.insert(metric!("sections.nonstandard_count"), nonstandard as f64);
    if !concatenated_names.is_empty() {
        metrics.insert(
            metric!("sections.name_entropy"),
            scan::entropy::shannon(&concatenated_names),
        );
    }
}

/// `true` when `name` matches a section name routinely produced by
/// upstream toolchains across PE/ELF/Mach-O. Packers and obfuscators
/// rename or invent sections (`.UPX0`, `.aspack`, random hex tags)
/// which trip `sections.nonstandard_count`. Membership is intentionally
/// loose — any section the test corpus shows in benign binaries is in.
pub(crate) fn is_well_known_section_name(name: &str) -> bool {
    // Mach-O sections come in as `SEGMENT,section` (e.g. `__TEXT,__text`).
    // Strip the segment prefix and check the section stem. For PE/ELF
    // we additionally strip a leading dot so dotted (`.text`) and
    // undotted (`text`) forms share the same lookup.
    let stem = name
        .rsplit_once(',')
        .map_or(name, |(_, s)| s)
        .trim_start_matches('.');
    matches!(
        stem,
        // PE / ELF — the canonical set.
        "text" | "rdata" | "data" | "bss" | "rodata" | "idata" | "edata"
        | "pdata" | "xdata" | "tls" | "reloc" | "rsrc" | "debug" | "init"
        | "fini" | "plt" | "got" | "got.plt" | "plt.got" | "plt.sec"
        | "dynamic" | "dynsym" | "dynstr" | "symtab" | "strtab" | "shstrtab"
        | "interp" | "note" | "hash" | "gnu.hash" | "gnu.version"
        | "gnu.version_r" | "gnu.version_d" | "eh_frame" | "eh_frame_hdr"
        | "comment" | "ARM.exidx" | "ARM.extab" | "ARM.attributes"
        | "init_array" | "fini_array" | "preinit_array" | "ctors" | "dtors"
        | "tbss" | "tdata" | "tm_clone_table" | "data.rel.ro"
        | "got.plt.sec" | "stab" | "stabstr" | "drectve" | "didat"
        // Mach-O segment,section combos (after dot-strip we still match the
        // common ones — the names below come from the typical Mach-O
        // layout where `Section.name` is `"__text"`, `"__data"`, etc.,
        // *without* the segment prefix).
        | "__text" | "__data" | "__bss" | "__cstring" | "__const"
        | "__objc_classlist" | "__objc_classrefs" | "__objc_data"
        | "__objc_classname" | "__objc_const" | "__objc_methname"
        | "__objc_methtype" | "__objc_selrefs" | "__objc_imageinfo"
        | "__la_symbol_ptr" | "__nl_symbol_ptr" | "__got" | "__stubs"
        | "__stub_helper" | "__cfstring" | "__unwind_info" | "__eh_frame"
        | "__info_plist" | "__swift5_proto" | "__swift5_types"
        | "__swift5_fieldmd" | "__swift5_typeref" | "__swift5_reflstr"
        | "__swift5_assocty" | "__swift5_capture" | "__swift5_builtin"
        | "__swift5_acfuncs" | "__swift5_mpenum" | "__llvm_covmap"
        | "__llvm_covfun" | "__llvm_prf_cnts" | "__llvm_prf_data"
        | "__llvm_prf_names" | "__llvm_prf_vnds"
    )
}

/// Cap on located high-entropy string spans. The count metric is exact; the
/// spans are a bounded sample for localisation.
const MAX_STRING_SPANS: usize = 64;

/// Cross-format `binary.*` aggregates derived from sections + strings +
/// raw bytes. Keeps the keys cleave's trait engine has used historically
/// without each format extractor re-deriving the same logic.
///
/// Emits (only the useful subset — fields cleave computed but no trait
/// queried were dropped):
/// - `binary.string_count`, `binary.max_string_length`,
///   `binary.avg_string_length`, `binary.high_entropy_string_count`.
/// - `binary.entropy_variance` — population variance across the
///   per-section entropies. Packers tend to flatten this; a normal
///   binary spreads across `.text` (~6), `.rodata` (~5), `.data` (~3).
/// - `binary.code_to_data_ratio`, `binary.largest_section_ratio` —
///   simple structural ratios over `Sections.file_size`.
///
/// The overlay keys come from [`emit_binary_overlay`].
pub(crate) fn emit_binary_aggregates(
    sections: &Sections,
    strings: &output::Strings,
    bytes: &[u8],
    metrics: &mut Metrics,
) {
    // -- Strings ------------------------------------------------------
    let total = strings.len();
    if total > 0 {
        let mut max_len = 0_usize;
        let mut max_string_span: Option<Span> = None;
        let mut sum_len = 0_usize;
        let mut high_entropy = 0_u64;
        let mut high_entropy_spans = SpanBuilder::with_cap(MAX_STRING_SPANS);
        let mut sentence = 0_u64;
        // Collect lengths once; second pass below computes stddev.
        let mut lengths: Vec<usize> = Vec::with_capacity(total);
        for (span, s) in strings.text_spans() {
            let len = s.len();
            if len > max_len {
                max_len = len;
                max_string_span = Some(span);
            }
            sum_len = sum_len.saturating_add(len);
            lengths.push(len);
            // Shannon-entropy floor of 6.0 bits/byte separates random-
            // looking strings (base64, keys, hex blobs) from English /
            // identifier-shaped text (~3–4.5).
            if scan::entropy::shannon(s.as_bytes()) >= 6.0 {
                high_entropy += 1;
                high_entropy_spans.push(span.offset, span.len);
            }
            if is_sentence_like(s) {
                sentence += 1;
            }
        }
        let avg = sum_len as f64 / total as f64;
        let variance = lengths
            .iter()
            .map(|&l| {
                let d = l as f64 - avg;
                d * d
            })
            .sum::<f64>()
            / total as f64;
        metrics.insert(metric!("binary.string_count"), total as f64);
        match max_string_span {
            Some(span) => {
                metrics.insert_located(metric!("binary.max_string_length"), max_len as f64, [span])
            }
            None => metrics.insert(metric!("binary.max_string_length"), max_len as f64),
        }
        metrics.insert(metric!("binary.avg_string_length"), avg);
        metrics.insert(metric!("binary.string_length_stddev"), variance.sqrt());
        metrics.insert_located(
            metric!("binary.high_entropy_string_count"),
            high_entropy as f64,
            high_entropy_spans.into_spans(),
        );
        metrics.insert(metric!("binary.sentence_string_count"), sentence as f64);
        metrics.insert(
            metric!("binary.sentence_string_ratio"),
            sentence as f64 / total as f64,
        );
    }

    // -- Per-section entropy variance --------------------------------
    let entropies: Vec<f64> = sections.iter().filter_map(|s| s.entropy).collect();
    if entropies.len() >= 2 {
        let mean = entropies.iter().sum::<f64>() / entropies.len() as f64;
        let var =
            entropies.iter().map(|e| (e - mean).powi(2)).sum::<f64>() / entropies.len() as f64;
        metrics.insert(metric!("binary.entropy_variance"), var);
    }

    // -- Section ratios + size-weighted entropy ----------------------
    // `binary.code_entropy` / `binary.data_entropy` are size-weighted
    // averages of per-section entropies. Weighting by `file_size` is
    // what packer detectors want — a tiny `.init` block at 7.9 entropy
    // shouldn't dominate the `.text` average.
    let mut code_size: u64 = 0;
    let mut data_size: u64 = 0;
    let mut largest: u64 = 0;
    let mut code_entropy_sum = 0.0_f64;
    let mut data_entropy_sum = 0.0_f64;
    let mut code_spans = Vec::new();
    let mut data_spans = Vec::new();
    for s in sections {
        let is_code = s.is_code();
        let is_data = s.is_writable() || s.has_flag(SectionFlag::Data);
        let on_disk = s.file_size;
        largest = largest.max(on_disk);
        let entropy = s.entropy.unwrap_or(0.0);
        if is_code {
            code_size = code_size.saturating_add(on_disk);
            code_entropy_sum += entropy * on_disk as f64;
            if on_disk > 0 {
                code_spans.push(Span::new(s.file_offset, on_disk));
            }
        } else if is_data {
            data_size = data_size.saturating_add(on_disk);
            data_entropy_sum += entropy * on_disk as f64;
            if on_disk > 0 {
                data_spans.push(Span::new(s.file_offset, on_disk));
            }
        }
    }
    if code_size > 0 {
        metrics.insert_located(
            metric!("binary.code_entropy"),
            code_entropy_sum / code_size as f64,
            code_spans,
        );
    }
    if data_size > 0 {
        metrics.insert_located(
            metric!("binary.data_entropy"),
            data_entropy_sum / data_size as f64,
            data_spans,
        );
    }
    // Both sums come from file-declared section sizes; adding them as `u64`
    // overflowed on forged sizes near `u64::MAX`, and saturating would skew
    // the ratio, so take it in floating point.
    let classified = code_size as f64 + data_size as f64;
    if classified > 0.0 {
        metrics.insert(
            metric!("binary.code_to_data_ratio"),
            code_size as f64 / classified,
        );
    }
    let file_size = bytes.len() as u64;
    if file_size > 0 && largest > 0 {
        let largest_spans = sections
            .iter()
            .filter(|s| s.file_size == largest && s.file_size > 0)
            .map(|s| Span::new(s.file_offset, s.file_size));
        metrics.insert_located(
            metric!("binary.largest_section_ratio"),
            largest as f64 / file_size as f64,
            largest_spans,
        );
    }
}

/// `binary.has_overlay`, `binary.overlay_size`, `binary.overlay_ratio`,
/// `binary.overlay_entropy` — bytes beyond the last on-disk section extent
/// and beyond `image_end` (PE installer droppers, ELF self-extractors).
/// `image_end` is the format's own end of image where that lies past the
/// sections: Mach-O's section-less `__LINKEDIT` segment (symbols, dyld
/// info, code signature) and the ELF section-header table would otherwise
/// read as an overlay on every binary. PE passes `None`: its overlay stays
/// "past the last section's raw data", Authenticode table included.
pub(crate) fn emit_binary_overlay(
    sections: &Sections,
    bytes: &[u8],
    image_end: Option<u64>,
    metrics: &mut Metrics,
) {
    // Last on-disk extent across sections and the format's own image end.
    let file_size = bytes.len() as u64;
    let last_extent = sections
        .as_slice()
        .iter()
        .map(|s| s.file_offset.saturating_add(s.file_size))
        .max()
        .unwrap_or(0)
        .max(image_end.unwrap_or(0));
    if last_extent > 0 && file_size > last_extent {
        let overlay_size = file_size - last_extent;
        metrics.insert(metric!("binary.has_overlay"), 1.0);
        metrics.insert(metric!("binary.overlay_size"), overlay_size as f64);
        metrics.insert(
            metric!("binary.overlay_ratio"),
            overlay_size as f64 / file_size as f64,
        );
        if let Some(overlay) = bytes
            .get(crate::bytes::sat_usize(last_extent)..)
            .filter(|overlay| !overlay.is_empty())
        {
            // The overlay is appended payload (installer stub, SFX); carry its
            // extent so a finding points past the last section.
            metrics.insert_located(
                metric!("binary.overlay_entropy"),
                scan::entropy::shannon(overlay),
                [Span::new(last_extent, overlay_size)],
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::Section;

    #[test]
    fn forged_section_sizes_do_not_overflow_the_code_data_ratio() {
        // Two sections each claiming nearly `u64::MAX` bytes: the code and
        // data sums used to be added unchecked.
        let section = |name: &str, flag: SectionFlag| Section {
            name: name.into(),
            vaddr: 0,
            vsize: 0,
            file_offset: 0,
            file_size: u64::MAX - 1,
            flags: vec![flag],
            flags_raw: None,
            entropy: Some(1.0),
        };
        let sections = Sections::from_iter([
            section("a", SectionFlag::Executable),
            section("b", SectionFlag::Data),
        ]);
        let mut metrics = Metrics::new();
        emit_binary_aggregates(&sections, &output::Strings::new(), b"x", &mut metrics);
        assert_eq!(
            metrics.get_key(&metric!("binary.code_to_data_ratio")),
            Some(0.5)
        );
    }

    /// Compiler and loader artifacts must not count as a public API.
    ///
    /// Any C++ binary built with exceptions exports Itanium-ABI RTTI, and every
    /// Mach-O executable exports its image header. A stub with no real exports
    /// reaches four on those alone, which is enough to satisfy an
    /// `exports.api_count >= 4` suppression and silence the obfuscation rules
    /// that would otherwise describe it.
    #[test]
    fn rtti_and_image_header_are_not_api_exports() {
        for artifact in [
            "__ZTISt9exception",
            "_ZTSSt11logic_error",
            "__ZTVN10__cxxabiv117__class_type_infoE",
            "__ZTTSt13basic_fstream",
            "_mh_execute_header",
            "mh_execute_header",
        ] {
            assert!(!is_api_export(artifact), "{artifact} should not count");
        }
    }

    #[test]
    fn ordinary_symbols_are_api_exports() {
        for real in ["_main", "curl_easy_init", "_SSL_connect", "ZLibDecompress"] {
            assert!(is_api_export(real), "{real} should count");
        }
    }
}
