//! Rizin's output: the `===SEP===`-delimited JSON tables, and how they fill
//! the typed symbol and section views.

use serde::Deserialize;

use crate::metric;
use crate::output::{Metrics, SectionFlag};

/// The blocks a script's output splits into, in order: three JSON tables,
/// the analysis pass's chatter, and the section table.
const BLOCKS: [&str; 5] = ["iij", "iEj", "analysis", "aflj", "iSj"];

/// Split rizin's combined stdout into a typed [`RizinRecovery`], and say
/// whether every table was present and well-formed.
///
/// The five blocks are, in order (see [`BLOCKS`]):
/// 1. `iij`  — JSON array of imports
/// 2. `iEj`  — JSON array of exports
/// 3. the analysis pass (`aaa`, `aa; aac`, …) — chatter, discarded
/// 4. `aflj` — JSON array of recovered functions
/// 5. `iSj`  — JSON array of sections
///
/// Each JSON block tolerates leading log chatter via [`parse_json_array`].
/// A missing or malformed table degrades to an empty one rather than failing
/// the whole recovery — partial data is more useful than none on adversarial
/// input — but is logged and reported as incomplete.
pub(super) fn parse_recovery_output(stdout: &str) -> (RizinRecovery, bool) {
    let blocks = output_blocks(stdout);
    let mut complete = blocks.len() == BLOCKS.len();
    if !complete {
        tracing::warn!(
            blocks = blocks.len(),
            expected = BLOCKS.len(),
            "rizin output: unexpected block count"
        );
    }
    let recovery = RizinRecovery {
        imports: table(&blocks, 0, &mut complete),
        exports: table(&blocks, 1, &mut complete),
        functions: table(&blocks, 3, &mut complete),
        sections: table(&blocks, 4, &mut complete),
    };
    (recovery, complete)
}

/// The JSON table in block `index`, or an empty one when the block is
/// missing or malformed. A malformed block clears `complete`; a missing one
/// already did, through the block count.
fn table<T: serde::de::DeserializeOwned>(
    blocks: &[&str],
    index: usize,
    complete: &mut bool,
) -> Vec<T> {
    let Some(block) = blocks.get(index) else {
        return Vec::new();
    };
    match parse_json_array(block) {
        Ok(rows) => rows,
        Err(error) => {
            *complete = false;
            tracing::warn!(
                table = BLOCKS.get(index).copied().unwrap_or("?"),
                block_bytes = block.len(),
                %error,
                "rizin output: malformed table dropped"
            );
            Vec::new()
        }
    }
}

/// Split rizin's stdout at the lines `echo ===SEP===` printed. Only a whole
/// line is a separator: names in the JSON blocks come from the analysed
/// binary, so an import named `===SEP===` must not split its block and shift
/// every later one out of place. JSON escapes newlines inside strings, so no
/// name can make up a line of its own.
fn output_blocks(stdout: &str) -> Vec<&str> {
    let mut blocks = Vec::new();
    let mut start = 0;
    let mut end = 0;
    for line in stdout.split_inclusive('\n') {
        end += line.len();
        if line.trim_end_matches(['\n', '\r']) == "===SEP===" {
            blocks.push(stdout.get(start..end - line.len()).unwrap_or_default());
            start = end;
        }
    }
    blocks.push(stdout.get(start..).unwrap_or_default());
    blocks
}

/// Upper bound on the function-name bytes [`RizinRecovery::apply`] copies to
/// resolve call targets by address. Every call site naming one function
/// copies that function's name, which the analysed binary chooses, so a long
/// symbol called from a million sites would otherwise copy gigabytes out of
/// a few megabytes of output. Call targets past the budget stay unresolved.
pub(super) const MAX_RESOLVED_NAME_BYTES: usize = 64 * 1024 * 1024;

/// Extract a JSON array out of `text`. Rizin sometimes prefixes
/// arrays with log lines; we tolerate that by scanning for `[`.
pub(super) fn parse_json_array<T: serde::de::DeserializeOwned>(
    text: &str,
) -> Result<Vec<T>, serde_json::Error> {
    let start = text.find('[').unwrap_or(0);
    serde_json::from_str(&text[start..])
}

/// Raw rizin output — converted into filefacts' unified [`crate::Symbol`]
/// and section views by [`Self::apply`] and [`Self::apply_with_sections`].
#[derive(Clone)]
pub(crate) struct RizinRecovery {
    pub(super) imports: Vec<RawImport>,
    pub(super) exports: Vec<RawExport>,
    pub(super) functions: Vec<RawFunction>,
    pub(super) sections: Vec<RawSection>,
}

/// Counts of entries rizin contributed to each typed view through
/// [`RizinRecovery::apply`]. Returned so format extractors can emit the
/// `*.recovered_*_count` metrics that say a view was filled in by
/// disassembly rather than by the format-native parser. The metric names
/// are tool-agnostic, so the schema does not name the disassembler.
#[derive(Default, Debug, Clone, Copy)]
pub(crate) struct RecoveryCounts {
    pub imports: u32,
    pub exports: u32,
    pub functions: u32,
    pub sections: u32,
}

impl RizinRecovery {
    /// Function ranges recovered by `aflj`, expressed as
    /// `(entry_va, size)`. PE-specific post-processing uses these ranges to
    /// associate native byte-pattern facts with their containing functions.
    pub(crate) fn function_ranges(&self) -> Vec<(u64, u64)> {
        self.functions
            .iter()
            .map(|function| (function.offset, function.size))
            .collect()
    }

    /// Direct inter-function call edges as
    /// `(caller_entry_va, callsite_va, target_va)`.
    pub(crate) fn direct_call_edges(&self) -> Vec<(u64, u64, u64)> {
        self.functions
            .iter()
            .flat_map(|function| {
                function.callrefs.iter().filter_map(move |callref| {
                    if !callref.is_call() {
                        return None;
                    }
                    Some((function.offset, callref.from?, callref.to?))
                })
            })
            .collect()
    }

    /// Push recovered symbols into the unified `Symbols` view and emit
    /// the rizin-specific `binary.*` metrics. Only fills slots that
    /// the format parser left empty — never overwrites existing data. For
    /// callers whose format parser always reads the section table.
    pub(crate) fn apply(
        self,
        symbols_out: &mut crate::Symbols,
        metrics: &mut Metrics,
    ) -> RecoveryCounts {
        self.apply_inner(symbols_out, None, metrics)
    }

    /// [`Self::apply`], and also fill an empty section table. PE / ELF /
    /// Mach-O extractors call this when the format parser found no sections
    /// (packed binaries are the common case).
    pub(crate) fn apply_with_sections(
        self,
        symbols_out: &mut crate::Symbols,
        sections_out: &mut Vec<crate::output::Section>,
        metrics: &mut Metrics,
    ) -> RecoveryCounts {
        self.apply_inner(symbols_out, Some(sections_out), metrics)
    }

    /// Discard the recovered exports. A PE whose optional header declares no
    /// export directory has no exports the loader can resolve, yet `iEj`
    /// still lists global symbols there — on every Go PE it reports the
    /// `gopclntab` COFF symbol. The caller knows the format; rizin does not.
    pub(crate) fn without_exports(mut self) -> Self {
        self.exports.clear();
        self
    }

    fn apply_inner(
        self,
        symbols_out: &mut crate::Symbols,
        sections_out: Option<&mut Vec<crate::output::Section>>,
        metrics: &mut Metrics,
    ) -> RecoveryCounts {
        use crate::output::{Symbol, SymbolKind};
        let mut counts = RecoveryCounts::default();
        let had_imports = symbols_out.iter().any(|s| s.kind() == SymbolKind::Import);
        let had_exports = symbols_out.iter().any(|s| s.kind() == SymbolKind::Export);
        let had_functions = symbols_out.iter().any(|s| s.kind() == SymbolKind::Function);
        let had_calls = symbols_out.iter().any(|s| s.kind() == SymbolKind::Call);
        let function_names: std::collections::HashMap<u64, String> = self
            .functions
            .iter()
            .filter(|function| !function.name.is_empty())
            .map(|function| (function.offset, function.name.clone()))
            .collect();
        let mut name_budget = MAX_RESOLVED_NAME_BYTES;
        let mut resolve = |callref: &RawCallref| -> Option<String> {
            if let Some(name) = &callref.name {
                return Some(name.clone());
            }
            let name = function_names.get(&callref.to?)?;
            name_budget = name_budget.checked_sub(name.len())?;
            Some(name.clone())
        };
        if !had_imports {
            for imp in self.imports {
                if imp.name.is_empty() {
                    continue;
                }
                symbols_out.push(Symbol::Import {
                    name: imp.name,
                    alias: None,
                    library: imp.libname,
                    // The PLT/stub address — where the binary references the
                    // import — anchors the finding, matching how recovered
                    // exports/functions store their vaddr. 0 means rizin gave
                    // no location, so leave it unanchored rather than at 0.
                    offset: (imp.plt != 0).then_some(imp.plt),
                    ordinal: imp.ordinal,
                });
                counts.imports = counts.imports.saturating_add(1);
            }
        }
        if !had_exports {
            for exp in self.exports {
                if exp.name.is_empty() {
                    continue;
                }
                symbols_out.push(Symbol::Export {
                    name: exp.name,
                    offset: Some(exp.vaddr),
                    ordinal: None,
                    forward_to: None,
                });
                counts.exports = counts.exports.saturating_add(1);
            }
        }
        if !had_functions && !self.functions.is_empty() {
            for func in &self.functions {
                if func.name.is_empty() {
                    continue;
                }
                let callees: Vec<String> = func
                    .callrefs
                    .iter()
                    .filter(|callref| callref.is_call())
                    .filter_map(&mut resolve)
                    .filter(|n| !n.is_empty())
                    .collect();
                symbols_out.push(Symbol::Function {
                    name: func.name.clone(),
                    offset: Some(func.offset),
                    complexity: func.cc,
                    callees,
                });
                counts.functions = counts.functions.saturating_add(1);
            }
            // Function-level aggregates. Complexity and basic blocks are what
            // `aflj` makes essentially free — signals a format parser cannot
            // produce on a stripped binary. `functions.count` is emitted
            // cross-format by `lib.rs::extract_all`, not here.
            let cc_values: Vec<u32> = self.functions.iter().filter_map(|f| f.cc).collect();
            if !cc_values.is_empty() {
                let sum: u64 = cc_values.iter().map(|&v| u64::from(v)).sum();
                metrics.insert(
                    metric!("binary.avg_complexity"),
                    sum as f64 / cc_values.len() as f64,
                );
                let max = cc_values.iter().copied().max().unwrap_or(0);
                metrics.insert(metric!("binary.max_complexity"), f64::from(max));
            }

            let bb_values: Vec<u32> = self.functions.iter().filter_map(|f| f.nbbs).collect();
            if !bb_values.is_empty() {
                let sum: u64 = bb_values.iter().map(|&v| u64::from(v)).sum();
                metrics.insert(
                    metric!("binary.avg_basic_blocks"),
                    sum as f64 / bb_values.len() as f64,
                );
                metrics.insert(metric!("binary.basic_block_count"), sum as f64);
            }

            // Function-shape bucket counts. Detection traits target the
            // tails of these distributions: a backdoor can add a single huge
            // function in a sea of tiny ones; obfuscators produce
            // sea-of-tiny shapes (one-block dispatch handlers per opcode);
            // leaf-heavy ratios indicate flattened control flow.
            // `nbbs >= 50` is the usual "non-trivial CFG" floor, and
            // `nbbs == 1` is rizin's shape for stubs.
            let huge = self
                .functions
                .iter()
                .filter(|f| f.nbbs.is_some_and(|n| n >= 50))
                .count();
            let tiny = self
                .functions
                .iter()
                .filter(|f| f.nbbs.is_some_and(|n| n == 1))
                .count();
            let leaf = self
                .functions
                .iter()
                .filter(|f| f.callrefs.is_empty() && f.nbbs.is_some())
                .count();
            metrics.insert(metric!("binary.huge_function_count"), huge as f64);
            metrics.insert(metric!("binary.tiny_function_count"), tiny as f64);
            metrics.insert(metric!("binary.leaf_function_count"), leaf as f64);
        }
        // `aflj.callrefs` carries concrete binary call sites even when the
        // target has no source-level symbol. Preserve direct CALL edges in
        // the same typed Call view used by source formats. Branch-only CODE
        // refs are deliberately excluded: they describe CFG edges within a
        // function, not function invocation.
        if !had_calls {
            for function in &self.functions {
                for callref in &function.callrefs {
                    if !callref.is_call() {
                        continue;
                    }
                    symbols_out.push(Symbol::Call {
                        target: resolve(callref),
                        args: Vec::new(),
                        offset: callref.from,
                    });
                }
            }
        }
        // Section recovery for packed/obfuscated binaries whose format parser
        // found no section table. Filled through the same `Section` view
        // every other extractor emits, with flags projected from rizin's perm
        // string (`-r-x` → readable, executable).
        if let Some(sections_out) = sections_out {
            if sections_out.is_empty() {
                for sec in self.sections {
                    if sec.name.is_empty() {
                        continue;
                    }
                    let flags = perm_to_flags(sec.perm.as_deref());
                    sections_out.push(crate::output::Section {
                        name: sec.name,
                        vaddr: sec.vaddr.unwrap_or(0),
                        vsize: sec.vsize.unwrap_or(sec.size),
                        file_offset: sec.paddr.unwrap_or(0),
                        file_size: sec.size,
                        flags,
                        flags_raw: None,
                        entropy: None,
                    });
                    counts.sections = counts.sections.saturating_add(1);
                }
            }
        }
        counts
    }
}

/// Map rizin's `perm` field (`-r-x`, `-rw-`, `-rwx`) to the canonical
/// flag vocabulary used by every other filefacts section view. Order is
/// `readable, writable, executable` so callers iterating the
/// resulting Vec in order get a stable shape.
fn perm_to_flags(perm: Option<&str>) -> Vec<SectionFlag> {
    let Some(p) = perm else {
        return Vec::new();
    };
    [
        ('r', SectionFlag::Readable),
        ('w', SectionFlag::Writable),
        ('x', SectionFlag::Executable),
    ]
    .into_iter()
    .filter_map(|(c, flag)| p.contains(c).then_some(flag))
    .collect()
}

// =============================================================================
// Wire-format deserialisers. Map rizin's JSON shape to internal structs;
// filefacts' public typed views (Import / Export / Function) stay independent.
// =============================================================================

#[derive(Clone, Deserialize)]
pub(super) struct RawImport {
    pub(super) name: String,
    pub(super) libname: Option<String>,
    pub(super) ordinal: Option<u32>,
    /// PLT/stub address rizin resolves for the import — the site where the
    /// binary actually calls through to the imported symbol. 0 (the serde
    /// default) means rizin couldn't place it; treated as "no location".
    #[serde(default)]
    pub(super) plt: u64,
}

#[derive(Clone, Deserialize)]
pub(super) struct RawExport {
    pub(super) name: String,
    #[serde(default)]
    pub(super) vaddr: u64,
}

#[derive(Clone, Deserialize)]
pub(super) struct RawFunction {
    pub(super) name: String,
    /// Function entry address.
    #[serde(default)]
    pub(super) offset: u64,
    /// Function byte size. Used only for correlating separately recovered
    /// native-code facts with their containing function.
    #[serde(default)]
    pub(super) size: u64,
    /// Cyclomatic complexity.
    #[serde(default)]
    pub(super) cc: Option<u32>,
    /// Number of basic blocks (feeds the `binary.*_basic_blocks` aggregates).
    #[serde(default)]
    pub(super) nbbs: Option<u32>,
    /// Outgoing code references. A reference without a `name` is resolved
    /// through the function table by its target address; one that still has
    /// no name keeps a `None` call target and is left out of `callees`.
    #[serde(default)]
    pub(super) callrefs: Vec<RawCallref>,
}

#[derive(Clone, Deserialize)]
pub(super) struct RawCallref {
    #[serde(default)]
    name: Option<String>,
    /// Virtual address of the call instruction.
    #[serde(default)]
    from: Option<u64>,
    /// Virtual address of the call target.
    #[serde(default)]
    to: Option<u64>,
    /// Rizin emits `CALL` for inter-function invocation and `CODE` for
    /// intra-function control-flow edges.
    #[serde(default, rename = "type")]
    kind: Option<String>,
}

impl RawCallref {
    fn is_call(&self) -> bool {
        self.kind
            .as_deref()
            .is_none_or(|kind| kind.eq_ignore_ascii_case("call"))
    }
}

/// Rizin `iSj` section entry. `paddr` / `vaddr` / `vsize` are optional
/// because rizin leaves them out for sections whose layout it could not
/// resolve.
#[derive(Clone, Deserialize)]
pub(super) struct RawSection {
    #[serde(default)]
    pub(super) name: String,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    vsize: Option<u64>,
    #[serde(default)]
    paddr: Option<u64>,
    #[serde(default)]
    vaddr: Option<u64>,
    #[serde(default)]
    perm: Option<String>,
}
