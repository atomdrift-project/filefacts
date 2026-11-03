//! Functions recovered from machine code, and the symbols and metrics they
//! yield on a binary whose format parser found no function inventory.
//!
//! [`binform`] recovers them in-process, along with the layout tables
//! (sections, imports, exports) a format parser that read none can take
//! instead. Everything downstream — the `binary.*` metrics, the typed
//! function and call views, the PE API-hash correlation — reads one
//! [`Functions`] value.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::metric;
use crate::output::Metrics;

/// The disk-cache key's part for function recovery. Bump it whenever the
/// binform commit in Cargo.lock, or what filefacts takes from it, changes:
/// either changes what a cached extraction holds.
pub(crate) const POLICY: &str = "binform=v5";

/// Recovered functions, and names for the call targets that are no
/// recovered function (an import's slot or stub).
#[derive(Clone, Debug, Default)]
pub(crate) struct Functions {
    pub(crate) recovery: binform::Functions,
    pub(crate) targets: HashMap<u64, String>,
}

/// binform's answer for one file: its functions, the layout tables a format
/// parser that read none can take instead, and the syscall sites it found.
#[derive(Clone, Debug, Default)]
pub(crate) struct Native {
    pub(crate) functions: Functions,
    pub(crate) imports: Vec<binform::Import>,
    pub(crate) exports: Vec<binform::Export>,
    pub(crate) sections: Vec<binform::Section>,
    /// Syscall sites, resolved while the `binform::Binary` was in scope.
    pub(crate) syscalls: Vec<SyscallFact>,
    /// The instruction set, for labelling the syscall table a number was
    /// resolved against.
    pub(crate) arch: Option<binform::Arch>,
}

/// One syscall site: a raw `syscall`/`svc` instruction, or a call to the libc
/// `syscall()` wrapper with a constant number (`via = Some("syscall")`). The
/// name is resolved against the binary's architecture; `args` are in syscall
/// order (arg 0 first), each a constant or a pointer with the bytes behind it.
#[derive(Clone, Debug)]
pub(crate) struct SyscallFact {
    pub(crate) addr: u64,
    pub(crate) number: u64,
    pub(crate) name: Option<&'static str>,
    pub(crate) via: Option<&'static str>,
    pub(crate) args: Vec<binform::Value>,
}

/// Counts of entries binform contributed to each typed view, so format
/// extractors can emit the `*.recovered_*_count` metrics that say a view
/// was filled in by binform rather than by the format-native parser.
#[derive(Default, Debug, Clone, Copy)]
pub(crate) struct RecoveryCounts {
    pub imports: u32,
    pub exports: u32,
    pub functions: u32,
    pub sections: u32,
}

/// binform's answer for `bytes`: always the layout it read, and the
/// functions of an instruction set it decodes (none otherwise). `None` when
/// it cannot read the file at all. A recovery its work budget cut short
/// still holds every function found within it, which is kept.
pub(crate) fn recover(bytes: &[u8]) -> Option<Native> {
    let image = match binform::parse(bytes) {
        Ok(image) => image,
        Err(error) => {
            count(&STATS.unreadable);
            tracing::debug!(%error, bytes = bytes.len(), "binform: unreadable");
            return None;
        }
    };
    let recovery = binform::functions(&image, &binform::Limits::DEFAULT);
    if image.arch.is_none() {
        count(&STATS.layout_only);
    } else if recovery.truncated {
        count(&STATS.truncated);
    } else {
        count(&STATS.recovered);
    }
    let mut targets = HashMap::new();
    for function in &recovery.functions {
        for r in &function.refs {
            if r.kind == binform::RefKind::Call
                && recovery.function(r.to).is_none()
                && let Some(name) = image.import(r.to)
            {
                targets.entry(r.to).or_insert_with(|| name.to_owned());
            }
        }
    }
    let syscalls = syscall_facts(&image, &recovery);
    Some(Native {
        functions: Functions { recovery, targets },
        imports: image.imports,
        exports: image.exports,
        sections: image.sections,
        syscalls,
        arch: image.arch,
    })
}

/// Project binform's call sites into syscall facts, while the `Binary` is in
/// scope to resolve numbers to names: a raw `syscall`/`svc` instruction, and a
/// call to the libc `syscall()` wrapper whose number argument is constant.
fn syscall_facts(image: &binform::Binary<'_>, recovery: &binform::Functions) -> Vec<SyscallFact> {
    use binform::{Target, Value};
    let calls = binform::calls(image, recovery);
    // Statically linked binaries reach `connect` through a thin libc wrapper
    // (`mov eax, 42; syscall`), so the sockaddr the program built is at the
    // *caller's* `call`, not at the syscall. Find those wrapper functions —
    // small ones that issue the connect syscall — so a call to one projects as
    // a connect with the caller's arguments, the same as a direct one.
    let connect = image.syscall_number("connect");
    let wrappers = connect_wrappers(recovery, &calls, connect);
    let mut facts = Vec::new();
    for call in calls {
        let import = |index: usize| image.imports.get(index).map(|i| i.name.as_str());
        let (number, name, via, args) = match call.target {
            Target::Syscall(number) => (number, image.syscall(number), None, call.args),
            // A direct call to the connect wrapper: the socket syscall it
            // issues, with the caller's arguments (the sockaddr among them).
            Target::Addr(to) if wrappers.contains(&to) => {
                (connect.unwrap_or_default(), Some("connect"), Some("wrapper"), call.args)
            }
            // A libc `syscall(number, a0, a1, …)` call: the number is the
            // first C argument, the rest are the syscall's arguments.
            Target::Import(index) if import(index) == Some("syscall") => {
                let Some(Value::Int(number)) = call.args.first() else {
                    continue;
                };
                let number = *number;
                let args = call.args.into_iter().skip(1).collect();
                (number, image.syscall(number), Some("syscall"), args)
            }
            // A libc `connect(fd, sockaddr, len)` call: the socket syscall it
            // issues, so its `sockaddr` argument decodes the same as a direct
            // `connect`. The number is the arch's, for a uniform record.
            Target::Import(index) if import(index) == Some("connect") => {
                let number = image.syscall_number("connect").unwrap_or_default();
                (number, Some("connect"), Some("connect"), call.args)
            }
            _ => continue,
        };
        facts.push(SyscallFact { addr: call.addr, number, name, via, args });
    }
    facts
}

/// The entries of functions that are thin `connect` syscall wrappers: small
/// functions that issue the connect syscall. A direct call to one is a connect
/// call carrying the caller's arguments. The size bound keeps a large function
/// that merely contains a connect from claiming all its callers.
fn connect_wrappers(
    recovery: &binform::Functions,
    calls: &[binform::Call],
    connect: Option<u64>,
) -> HashSet<u64> {
    /// A libc syscall wrapper is a handful of instructions; glibc's `connect`
    /// is ~150 bytes with its cancellation path.
    const MAX_WRAPPER_SIZE: u64 = 512;
    let Some(connect) = connect else {
        return HashSet::new();
    };
    let mut wrappers = HashSet::new();
    for call in calls {
        if call.target != binform::Target::Syscall(connect) {
            continue;
        }
        // The connect syscall sits inside its wrapper, so find the small
        // function that contains the site (`function()` matches entries only).
        for function in &recovery.functions {
            let end = function.entry.wrapping_add(function.size);
            if (function.entry..end).contains(&call.addr) && function.size <= MAX_WRAPPER_SIZE {
                wrappers.insert(function.entry);
            }
        }
    }
    wrappers
}

/// Upper bound on the function-name bytes [`Functions::apply`] copies to
/// name call targets. Every call site naming one function copies that
/// function's name, which the analysed binary chooses, so a long symbol
/// called from a million sites would otherwise copy gigabytes. Call targets
/// past the budget stay unnamed.
pub(crate) const MAX_RESOLVED_NAME_BYTES: usize = 64 * 1024 * 1024;

/// The name a function without a symbol goes by: rizin's spelling, so the
/// typed function view reads the same whichever tool recovered it.
fn anonymous(entry: u64) -> String {
    format!("fcn.{entry:08x}")
}

impl Functions {
    /// Function ranges as `(entry_va, size)`, for correlating native
    /// byte-pattern facts with their containing functions.
    pub(crate) fn ranges(&self) -> Vec<(u64, u64)> {
        self.recovery
            .functions
            .iter()
            .map(|function| (function.entry, function.size))
            .collect()
    }

    /// Direct calls as `(caller_entry_va, callsite_va, target_va)`.
    pub(crate) fn call_edges(&self) -> Vec<(u64, u64, u64)> {
        self.recovery
            .functions
            .iter()
            .flat_map(|function| {
                function
                    .refs
                    .iter()
                    .filter(|r| r.kind == binform::RefKind::Call)
                    .map(move |r| (function.entry, r.from, r.to))
            })
            .collect()
    }

    /// The name of what a call to `to` reaches, if it is known.
    fn target(&self, to: u64) -> Option<String> {
        if let Some(name) = self.targets.get(&to) {
            return Some(name.clone());
        }
        let function = self.recovery.function(to)?;
        Some(function.name.clone().unwrap_or_else(|| anonymous(to)))
    }

    /// Push the functions and their calls into the typed views, and emit the
    /// `binary.*` function metrics. Fills only views the format parser left
    /// empty. Returns how many functions it added.
    pub(crate) fn apply(&self, symbols: &mut crate::Symbols, metrics: &mut Metrics) -> u32 {
        use crate::output::{Symbol, SymbolKind};
        let had_functions = symbols.iter().any(|s| s.kind() == SymbolKind::Function);
        let had_calls = symbols.iter().any(|s| s.kind() == SymbolKind::Call);
        let functions = &self.recovery.functions;
        let mut budget = MAX_RESOLVED_NAME_BYTES;
        let mut resolve = |to: u64| -> Option<String> {
            let name = self.target(to)?;
            budget = budget.checked_sub(name.len())?;
            Some(name)
        };
        let mut added = 0_u32;
        if !had_functions && !functions.is_empty() {
            for function in functions {
                let callees: Vec<String> = function
                    .refs
                    .iter()
                    .filter(|r| r.kind == binform::RefKind::Call)
                    .filter_map(|r| resolve(r.to))
                    .filter(|name| !name.is_empty())
                    .collect();
                symbols.push(Symbol::Function {
                    name: function
                        .name
                        .clone()
                        .filter(|name| !name.is_empty())
                        .unwrap_or_else(|| anonymous(function.entry)),
                    offset: Some(function.entry),
                    complexity: Some(function.complexity),
                    callees,
                });
                added = added.saturating_add(1);
            }
            emit_metrics(functions, metrics);
        }
        // Direct calls, in the same typed Call view source formats use.
        // Jumps and branches describe control flow inside a function, not an
        // invocation, and are left out.
        if !had_calls {
            for function in functions {
                for r in &function.refs {
                    if r.kind == binform::RefKind::Call {
                        symbols.push(Symbol::Call {
                            target: resolve(r.to),
                            args: Vec::new(),
                            offset: Some(r.from),
                        });
                    }
                }
            }
        }
        added
    }
}

/// Complexity, basic-block and function-shape aggregates: signals a format
/// parser cannot produce on a stripped binary. `functions.count` is emitted
/// cross-format by `lib.rs::extract_all`, not here.
fn emit_metrics(functions: &[binform::Function], metrics: &mut Metrics) {
    let n = functions.len() as f64;
    let complexity: u64 = functions.iter().map(|f| u64::from(f.complexity)).sum();
    let max = functions.iter().map(|f| f.complexity).max().unwrap_or(0);
    metrics.insert(metric!("binary.avg_complexity"), complexity as f64 / n);
    metrics.insert(metric!("binary.max_complexity"), f64::from(max));
    let blocks: u64 = functions.iter().map(|f| u64::from(f.blocks)).sum();
    metrics.insert(metric!("binary.avg_basic_blocks"), blocks as f64 / n);
    metrics.insert(metric!("binary.basic_block_count"), blocks as f64);
    // Detection traits target the tails: a backdoor can add one huge
    // function to a sea of tiny ones; obfuscators produce seas of one-block
    // dispatch handlers; leaf-heavy ratios indicate flattened control flow.
    // 50 blocks is the usual floor of a non-trivial CFG; a leaf makes no
    // calls (its jumps and branches are its own control flow).
    let huge = functions.iter().filter(|f| f.blocks >= 50).count();
    let tiny = functions.iter().filter(|f| f.blocks == 1).count();
    let leaf = functions
        .iter()
        .filter(|f| f.refs.iter().all(|r| r.kind != binform::RefKind::Call))
        .count();
    metrics.insert(metric!("binary.huge_function_count"), huge as f64);
    metrics.insert(metric!("binary.tiny_function_count"), tiny as f64);
    metrics.insert(metric!("binary.leaf_function_count"), leaf as f64);
}

/// How each recovery ended, process-wide.
#[derive(Debug, Default)]
struct Counters {
    recovered: AtomicU64,
    truncated: AtomicU64,
    layout_only: AtomicU64,
    unreadable: AtomicU64,
}

static STATS: Counters = Counters {
    recovered: AtomicU64::new(0),
    truncated: AtomicU64::new(0),
    layout_only: AtomicU64::new(0),
    unreadable: AtomicU64::new(0),
};

fn count(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// Log how each binform recovery ended.
pub(crate) fn log_stats() {
    tracing::info!(
        recovered = STATS.recovered.load(Ordering::Relaxed),
        truncated = STATS.truncated.load(Ordering::Relaxed),
        layout_only = STATS.layout_only.load(Ordering::Relaxed),
        unreadable = STATS.unreadable.load(Ordering::Relaxed),
        "binform recovery stats"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn function(entry: u64, blocks: u32, refs: Vec<binform::Ref>) -> binform::Function {
        binform::Function {
            entry,
            size: 16,
            blocks,
            complexity: 1,
            refs,
            name: None,
        }
    }

    fn recovery(functions: Vec<binform::Function>) -> binform::Functions {
        binform::Functions {
            functions,
            code: 100,
            covered: 100,
            ..binform::Functions::default()
        }
    }

    #[test]
    fn calls_are_named_by_import_symbol_or_address() {
        let call = |from, to| binform::Ref {
            from,
            to,
            kind: binform::RefKind::Call,
        };
        let mut named = function(0x2000, 1, Vec::new());
        named.name = Some("helper".into());
        let caller = function(
            0x1000,
            2,
            vec![
                call(0x1004, 0x2000),
                call(0x1008, 0x3000),
                call(0x100c, 0x9000),
                call(0x1010, 0x7777),
            ],
        );
        let functions = Functions {
            recovery: recovery(vec![caller, named, function(0x3000, 1, Vec::new())]),
            targets: HashMap::from([(0x9000, "connect".to_string())]),
        };
        let mut symbols = crate::Symbols::default();
        let mut metrics = Metrics::default();
        assert_eq!(functions.apply(&mut symbols, &mut metrics), 3);
        let first = symbols.iter().next().and_then(|s| match s {
            crate::output::Symbol::Function { name, callees, .. } => {
                Some((name.clone(), callees.clone()))
            }
            _ => None,
        });
        assert_eq!(
            first,
            Some((
                "fcn.00001000".to_string(),
                vec![
                    "helper".to_string(),
                    "fcn.00003000".to_string(),
                    "connect".to_string()
                ]
            ))
        );
        assert_eq!(
            metrics.get_key(&metric!("binary.leaf_function_count")),
            Some(2.0)
        );
        assert_eq!(
            metrics.get_key(&metric!("binary.tiny_function_count")),
            Some(2.0)
        );
    }
}
