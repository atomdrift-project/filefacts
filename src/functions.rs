//! Functions recovered from machine code, and the symbols and metrics they
//! yield on a binary whose format parser found no function inventory.
//!
//! [`binform`] recovers them in-process from the layout each format
//! extractor reads once (`formats::common::read_layout`), the same layout
//! its section, import and export views come from. Everything downstream —
//! the `binary.*` metrics, the typed function and call views, the PE
//! API-hash correlation — reads one [`Functions`] value.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::metric;
use crate::output::Metrics;

/// The disk-cache key's part for function recovery. Bump it whenever the
/// binform commit in Cargo.lock, or what filefacts takes from it, changes:
/// either changes what a cached extraction holds.
pub(crate) const POLICY: &str = "binform=v10";

/// Recovered functions, and names for the call targets that are no
/// recovered function (an import's slot or stub).
#[derive(Clone, Debug, Default)]
pub(crate) struct Functions {
    pub(crate) recovery: binform::Recovery,
    pub(crate) targets: HashMap<u64, String>,
}

/// binform's answer for one file: its functions and the syscall sites it
/// found.
#[derive(Clone, Debug, Default)]
pub(crate) struct Native {
    pub(crate) functions: Functions,
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

/// binform's answer for the binary `image` is the layout of: the functions
/// of an instruction set it decodes (none otherwise). `None` when binform
/// could not read the file at all, and so there is no layout. A recovery its
/// work budget cut short still holds every function found within it, which
/// is kept.
pub(crate) fn recover(image: Option<&binform::Binary<'_>>) -> Option<Native> {
    let Some(image) = image else {
        count(&STATS.unreadable);
        return None;
    };
    // A panic here would otherwise discard every other fact about the file.
    let recovery = match crate::panic_guard::catch_infallible(|| {
        binform::recover(image, &binform::Limits::DEFAULT)
    }) {
        Ok(recovery) => recovery,
        Err(panic) => {
            tracing::warn!(%panic, "binform function recovery panicked; functions skipped");
            count(&STATS.panicked);
            return None;
        }
    };
    if image.arch().is_none() {
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
                && let binform::Dest::Slot { addr, .. } = r.to
                && let Some(name) = recovery.name(image, r.to)
            {
                targets.entry(addr).or_insert_with(|| name.to_owned());
            }
        }
    }
    let syscalls = syscall_facts(image, &recovery);
    Some(Native {
        functions: Functions { recovery, targets },
        syscalls,
        arch: image.arch(),
    })
}

/// Project binform's call sites into syscall facts, while the `Binary` is in
/// scope to resolve numbers to names: a raw `syscall`/`svc` instruction, and a
/// call to the libc `syscall()` wrapper whose number argument is constant.
fn syscall_facts(image: &binform::Binary<'_>, recovery: &binform::Recovery) -> Vec<SyscallFact> {
    use binform::{Target, Value};
    let calls = binform::calls(image, &walkable(recovery));
    // Statically linked binaries reach `connect` through a thin libc wrapper
    // (`mov eax, 42; syscall`), so the sockaddr the program built is at the
    // *caller's* `call`, not at the syscall. Find those wrapper functions —
    // small ones that issue the connect syscall — so a call to one projects as
    // a connect with the caller's arguments, the same as a direct one.
    let connect = image.syscall_number("connect");
    let wrappers = match connect {
        Some(connect) => connect_wrappers(
            recovery,
            calls
                .iter()
                .filter(|call| call.target == Target::Syscall(Some(connect)))
                .map(|call| call.addr),
        ),
        None => HashSet::new(),
    };
    let mut facts = Vec::new();
    for call in calls {
        let import = |index: usize| image.imports().get(index).map(|i| i.name.as_str());
        let (number, name, via, args) = match call.target {
            Target::Syscall(Some(number)) => (number, image.syscall(number), None, call.args),
            // A direct call to the connect wrapper: the socket syscall it
            // issues, with the caller's arguments (the sockaddr among them).
            Target::Addr(to) if wrappers.contains(&to) => (
                connect.unwrap_or_default(),
                Some("connect"),
                Some("wrapper"),
                call.args,
            ),
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
            Target::Import(index) if import(index) == Some("connect") => (
                connect.unwrap_or_default(),
                Some("connect"),
                Some("connect"),
                call.args,
            ),
            _ => continue,
        };
        facts.push(SyscallFact {
            addr: call.addr,
            number,
            name,
            via,
            args,
        });
    }
    facts
}

/// Past this many times the code, recovered function extents are clipped
/// for the call walk; see [`walkable`].
const MAX_WALK_FACTOR: u64 = 2;

/// `recovery` as binform's call walk should see it. The walk reads each
/// function linearly over its whole extent, and extents that run on through
/// tails other functions share can sum to a thousand times the code (an x86
/// ELF), costing that sum in time and in call records. Past
/// [`MAX_WALK_FACTOR`], each function is walked only up to the next one's
/// entry, whose own walk covers the code that follows.
fn walkable(recovery: &binform::Recovery) -> Cow<'_, binform::Recovery> {
    let extent = recovery
        .functions
        .iter()
        .fold(0_u64, |sum, function| sum.saturating_add(function.size));
    if extent <= recovery.code.saturating_mul(MAX_WALK_FACTOR) {
        return Cow::Borrowed(recovery);
    }
    tracing::debug!(
        target: "filefacts::functions",
        extent,
        code = recovery.code,
        "function extents overlap; call walk clipped at each next entry"
    );
    let mut clipped = recovery.clone();
    let nexts: Vec<Option<u64>> = clipped
        .functions
        .iter()
        .skip(1)
        .map(|function| Some(function.entry))
        .chain([None])
        .collect();
    for (function, next) in clipped.functions.iter_mut().zip(nexts) {
        if let Some(gap) = next.and_then(|next| next.checked_sub(function.entry)) {
            function.size = function.size.min(gap);
        }
    }
    Cow::Owned(clipped)
}

/// The entries of functions that are thin `connect` syscall wrappers: small
/// functions holding one of the connect syscall `sites`. A direct call to one
/// is a connect call carrying the caller's arguments. The size bound keeps a
/// large function that merely contains a connect from claiming all its
/// callers.
fn connect_wrappers(
    recovery: &binform::Recovery,
    sites: impl IntoIterator<Item = u64>,
) -> HashSet<u64> {
    /// A libc syscall wrapper is a handful of instructions; glibc's `connect`
    /// is ~150 bytes with its cancellation path.
    const MAX_WRAPPER_SIZE: u64 = 512;
    let functions = &recovery.functions;
    let mut wrappers = HashSet::new();
    for site in sites {
        // The connect syscall sits inside its wrapper, which starts less
        // than `MAX_WRAPPER_SIZE` bytes before it; functions are in entry
        // order, so only those entries are candidates.
        let first = functions.partition_point(|f| f.entry.saturating_add(MAX_WRAPPER_SIZE) <= site);
        let last = functions.partition_point(|f| f.entry <= site);
        for function in functions.get(first..last).unwrap_or_default() {
            if function.size <= MAX_WRAPPER_SIZE && site - function.entry < function.size {
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

/// The name a function without a symbol goes by: `fcn.<entry in hex>`, a
/// stable spelling traits match on.
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
                    .map(move |r| (function.entry, r.from, r.addr()))
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
        let had_functions = crate::formats::common::has_functions(symbols);
        let had_calls = symbols.iter_kind(SymbolKind::Call).next().is_some();
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
                    .filter_map(|r| resolve(r.addr()))
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
                            target: resolve(r.addr()),
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
#[derive(Debug)]
struct Counters {
    recovered: AtomicU64,
    truncated: AtomicU64,
    layout_only: AtomicU64,
    unreadable: AtomicU64,
    panicked: AtomicU64,
}

static STATS: Counters = Counters {
    recovered: AtomicU64::new(0),
    truncated: AtomicU64::new(0),
    layout_only: AtomicU64::new(0),
    unreadable: AtomicU64::new(0),
    panicked: AtomicU64::new(0),
};

fn count(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// How the function recoveries in this process have ended, counted since it
/// started: for a host's telemetry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecoveryStats {
    /// Recoveries that decoded the image's instruction set to completion.
    pub recovered: u64,
    /// Recoveries cut short by a work limit.
    pub truncated: u64,
    /// Images whose layout was read but whose instruction set is not decoded.
    pub layout_only: u64,
    /// Images whose layout could not be read.
    pub unreadable: u64,
    /// Recoveries abandoned because binform panicked.
    pub panicked: u64,
}

/// How the binform function recoveries in this process have ended so far,
/// for a host's telemetry.
#[must_use]
pub fn recovery_stats() -> RecoveryStats {
    RecoveryStats {
        recovered: STATS.recovered.load(Ordering::Relaxed),
        truncated: STATS.truncated.load(Ordering::Relaxed),
        layout_only: STATS.layout_only.load(Ordering::Relaxed),
        unreadable: STATS.unreadable.load(Ordering::Relaxed),
        panicked: STATS.panicked.load(Ordering::Relaxed),
    }
}

#[cfg(test)]
mod tests;
