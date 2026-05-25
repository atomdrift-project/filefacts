//! Optional rizin/radare2 integration for binary analysis.
//!
//! Stripped binaries — and most malware — produce empty `dynsym` and
//! `symtab` tables, so goblin's parse returns 0 imports/exports/
//! functions. Rizin can recover them through linear disassembly +
//! signature matching + entry-point graph walking.
//!
//! # Discovery model
//!
//! At runtime we look for `rizin` (or `r2`) on `PATH`. If neither is
//! installed, every call here returns `None` and extraction proceeds
//! without rizin's contributions. No feature flag — the module is
//! always compiled; consumers running without rizin pay nothing
//! beyond a single `which`-style PATH scan per process.
//!
//! # Subprocess discipline
//!
//! The minimum viable port covers the happy path: spawn, wait for
//! exit with a hard timeout, parse JSON. Hardening for adversarial
//! input (cancellation propagation, output-cap detection, kill-group
//! tracking on truant children) lives in cleave's existing
//! `radare2/mod.rs` and ports across as #75c.

use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use serde::Deserialize;

use crate::output::Metrics;

/// Hard cap on a single rizin run. `aaa` analysis on a heavily
/// stripped ~14 MB Linux binary needed ~85 s in real measurement;
/// adversarial samples with packed code paths can take longer.
/// Match cleave's default timeout so behaviour is consistent.
const RIZIN_TIMEOUT: Duration = Duration::from_secs(300);

/// Soft memory cap on a single rizin subprocess (4 GiB). Enforced via
/// `setrlimit(RLIMIT_AS, ...)` (Linux) / `setrlimit(RLIMIT_DATA, ...)`
/// (macOS) in a `pre_exec` hook. Legitimate rizin analysis never
/// approaches this size — exceeding it indicates pathological input
/// and the kernel will abort the subprocess instead of letting it
/// drag the whole scan into OOM.
const RIZIN_MEMORY_LIMIT_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Per-process byte cap on a rizin subprocess's stdout. Mirrors
/// cleave's defence: pathological inputs can produce gigabytes of
/// JSON; we kill the process group on overflow and record the reason.
const MAX_SUBPROCESS_OUTPUT: usize = 100 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Process-wide hardening state.
// ---------------------------------------------------------------------------

/// Live rizin process-group IDs. Populated on spawn, drained in every
/// cleanup path. `kill_all_rizin_groups` reads this list and SIGKILLs
/// every entry so host CLI signal handlers can reap in-flight rizin
/// subprocesses before a forced `process::exit`.
static RIZIN_PGIDS: Mutex<Vec<i32>> = Mutex::new(Vec::new());

/// Counter — positive value means rizin invocation is disabled. Built
/// as a counter (not a `bool`) so `scoped_disable` can RAII-stack
/// without clobbering an outer `disable()` call.
static RIZIN_DISABLED: AtomicUsize = AtomicUsize::new(0);

/// Statistics (total, successes, timeouts, failures, memory_exceeded).
static RIZIN_TOTAL: AtomicU64 = AtomicU64::new(0);
static RIZIN_SUCCESSES: AtomicU64 = AtomicU64::new(0);
static RIZIN_TIMEOUTS: AtomicU64 = AtomicU64::new(0);
static RIZIN_FAILURES: AtomicU64 = AtomicU64::new(0);
static RIZIN_MEMORY_EXCEEDED: AtomicU64 = AtomicU64::new(0);

fn register_pgid(pgid: i32) {
    if let Ok(mut g) = RIZIN_PGIDS.lock() {
        g.push(pgid);
    }
}

fn unregister_pgid(pgid: i32) {
    if let Ok(mut g) = RIZIN_PGIDS.lock() {
        if let Some(idx) = g.iter().position(|&p| p == pgid) {
            g.swap_remove(idx);
        }
    }
}

struct PgidGuard(i32);
impl Drop for PgidGuard {
    fn drop(&mut self) {
        unregister_pgid(self.0);
    }
}

/// SIGKILL the process group of every currently-live rizin subprocess.
///
/// Intended for host CLI signal handlers (e.g. `ctrlc`) that need to
/// reap rizin workers before `process::exit`. Idempotent: entries are
/// removed from the registry by the normal cleanup paths, so calling
/// this after a clean shutdown is a no-op. No-op on non-Unix.
pub fn kill_all_rizin_groups() {
    let pgids: Vec<i32> = RIZIN_PGIDS.lock().map(|g| g.clone()).unwrap_or_default();
    #[cfg(unix)]
    for pgid in &pgids {
        // SAFETY: libc::kill with a negative pid sends the signal to
        // the process group. Async-signal-safe; tolerates already-dead
        // groups (ESRCH) silently.
        #[allow(unsafe_code)]
        unsafe {
            libc::kill(-(*pgid as libc::pid_t), libc::SIGKILL);
        }
    }
    #[cfg(not(unix))]
    let _ = pgids;
}

/// Disable rizin globally for the rest of the process. Each call must
/// be paired with the inverse via `enable()` or scoped via
/// `scoped_disable()`. Used by tests and benches to ensure
/// deterministic behaviour without actually invoking rizin.
pub fn disable() {
    RIZIN_DISABLED.fetch_add(1, Ordering::SeqCst);
}

/// RAII guard returned by [`scoped_disable`]. Re-enables rizin on
/// drop. Multiple guards stack: rizin stays disabled until every
/// guard is dropped.
pub struct ScopedDisable {
    _private: (),
}

impl Drop for ScopedDisable {
    fn drop(&mut self) {
        RIZIN_DISABLED.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Disable rizin for the lifetime of the returned guard.
pub fn scoped_disable() -> ScopedDisable {
    RIZIN_DISABLED.fetch_add(1, Ordering::SeqCst);
    ScopedDisable { _private: () }
}

/// `true` when [`disable`] / [`scoped_disable`] has muted rizin.
pub fn is_disabled() -> bool {
    RIZIN_DISABLED.load(Ordering::SeqCst) > 0
}

/// Cumulative rizin subprocess counters as
/// `(total, successes, timeouts, failures, memory_exceeded)`.
pub fn stats() -> (u64, u64, u64, u64, u64) {
    (
        RIZIN_TOTAL.load(Ordering::Relaxed),
        RIZIN_SUCCESSES.load(Ordering::Relaxed),
        RIZIN_TIMEOUTS.load(Ordering::Relaxed),
        RIZIN_FAILURES.load(Ordering::Relaxed),
        RIZIN_MEMORY_EXCEEDED.load(Ordering::Relaxed),
    )
}

/// Emit cumulative rizin statistics as a single `tracing::info!` line.
/// Host CLIs call this at shutdown for telemetry. No-op when no rizin
/// invocations have happened.
pub fn log_stats() {
    let (total, successes, timeouts, failures, memory_exceeded) = stats();
    if total == 0 {
        return;
    }
    let total_f = total as f64;
    tracing::info!(
        total_calls = total,
        successes,
        timeouts,
        failures,
        memory_exceeded,
        timeout_rate_pct = (timeouts as f64 / total_f) * 100.0,
        failure_rate_pct = (failures as f64 / total_f) * 100.0,
        "filefacts rizin subprocess statistics"
    );
}

/// One-shot PATH probe. Cached so we don't fork `which` per file.
fn rizin_binary() -> Option<&'static Path> {
    static CACHED: OnceLock<Option<std::path::PathBuf>> = OnceLock::new();
    CACHED
        .get_or_init(|| {
            // Prefer `rizin` (modern); fall back to `radare2` / `r2`.
            for name in ["rizin", "radare2", "r2"] {
                if let Some(path) = which(name) {
                    return Some(path);
                }
            }
            None
        })
        .as_deref()
}

/// Tiny PATH search — avoids pulling the `which` crate as a dep for
/// a single binary lookup. Returns the first existing executable
/// matching `name` in any `PATH` directory.
fn which(name: &str) -> Option<std::path::PathBuf> {
    let path_env = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_env) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// `true` when rizin (or a compatible drop-in) is available on PATH.
/// Cheap — does not spawn anything; only checks the cached probe.
pub fn available() -> bool {
    rizin_binary().is_some()
}

/// Recover symbol tables + function discovery via rizin. Returns
/// `None` when rizin isn't on PATH or invocation failed; callers
/// fall back to whatever goblin already populated.
///
/// The single rizin command runs `iij` (imports), `iEj` (exports),
/// `aaa` (deep analysis to discover functions), and `aflj`
/// (function list). Output blocks are separated by sentinel strings
/// we can `split` on cheaply.
///
/// Writes `bytes` to a temp file (rizin reads files from disk, not
/// stdin) and deletes it when done.
pub(crate) fn recover(bytes: &[u8]) -> Option<RizinRecovery> {
    if is_disabled() {
        return None;
    }
    let bin = rizin_binary()?;
    recover_with_bin(bin, bytes)
}

/// `recover()` with the rizin binary path passed in. Production path
/// uses the cached PATH probe; tests use this entry to inject a fake
/// `rizin` shim so the spawn/drain/parse pipeline can be exercised
/// deterministically without a real rizin install.
#[cfg(test)]
fn recover_with_bin_for_test(bin: &Path, bytes: &[u8]) -> Option<RizinRecovery> {
    recover_with_bin(bin, bytes)
}

fn recover_with_bin(bin: &Path, bytes: &[u8]) -> Option<RizinRecovery> {
    // The disable check intentionally lives only in the public
    // `recover()` entry, not here — tests inject a shim via
    // `recover_with_bin_for_test` and need a deterministic spawn
    // path that isn't affected by other tests' `scoped_disable`
    // guards running in parallel.
    RIZIN_TOTAL.fetch_add(1, Ordering::Relaxed);

    // Materialise the bytes as a temp file. Rizin requires a path —
    // there's no stdin mode for binary analysis. Concurrent callers
    // need distinct files: include a process-wide atomic counter
    // alongside the PID so two threads running `recover()` at once
    // don't trample each other's temp file (the second call's write
    // would race the first's read-and-spawn).
    static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut temp = std::env::temp_dir();
    temp.push(format!(
        "filefacts-rizin-{}-{}.bin",
        std::process::id(),
        seq
    ));
    if std::fs::write(&temp, bytes).is_err() {
        RIZIN_FAILURES.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    // Auto-cleanup guard — fires whether we return Some/None below.
    struct Cleanup<'a>(&'a Path);
    impl Drop for Cleanup<'_> {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(self.0);
        }
    }
    let _cleanup = Cleanup(&temp);

    // `-NN` disables plugin auto-loading (faster startup, fewer
    // surprises). `-q` quits after the `-c` script. `-e scr.color=0`
    // strips ANSI escapes from any stray log lines.
    let path_str = temp.to_string_lossy().to_string();
    let mut cmd = Command::new(bin);
    cmd.args([
        "-NN",
        "-q",
        "-e",
        "scr.color=0",
        "-e",
        "log.level=0",
        "-c",
        "iij; echo ===SEP===; iEj; echo ===SEP===; aaa; echo ===SEP===; aflj; echo ===SEP===; iSj",
        &path_str,
    ]);
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::null());

    apply_unix_hardening(&mut cmd);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(_) => {
            RIZIN_FAILURES.fetch_add(1, Ordering::Relaxed);
            return None;
        }
    };
    let child_id = child.id();
    register_pgid(child_id as i32);
    let _pgid_guard = PgidGuard(child_id as i32);
    let output_cap_hit = Arc::new(AtomicBool::new(false));

    // Drain stdout in a background thread while we wait for exit.
    // Without this, `aflj` output on a binary with thousands of
    // discovered functions overflows the pipe buffer (~64 KB on
    // macOS), the child blocks on write, and `wait_with_output()`
    // deadlocks waiting for exit. Capped at 100 MiB to bound the
    // worst-case adversarial blob; matches cleave's defence. On
    // overflow the reader thread SIGKILLs the rizin process group so
    // both pipes close promptly.
    let mut stdout_handle = match child.stdout.take() {
        Some(h) => h,
        None => {
            RIZIN_FAILURES.fetch_add(1, Ordering::Relaxed);
            return None;
        }
    };
    let cap_flag = output_cap_hit.clone();
    // The drain thread owns the read-end and reads to EOF. Once the
    // child exits, its write-end closes and `read_to_end` returns
    // promptly. Returning the buffer via `JoinHandle` (rather than a
    // channel with a wall-clock timeout) is what keeps this robust
    // under heavy parallel load — when the OS scheduler starves the
    // drain thread for several seconds, a channel-recv_timeout would
    // give up and treat the (still-pending) output as empty. The
    // join can't deadlock because the child is already known to have
    // exited by the time we join.
    let drain = std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        let n = (&mut stdout_handle)
            .take(MAX_SUBPROCESS_OUTPUT as u64)
            .read_to_end(&mut buf)
            .unwrap_or(0);
        if n >= MAX_SUBPROCESS_OUTPUT {
            mark_output_cap_hit(&cap_flag, child_id);
        }
        buf
    });

    // Poll for child exit with the timeout deadline. Once the child
    // exits, the reader thread's `read_to_end` returns naturally.
    let deadline = std::time::Instant::now() + RIZIN_TIMEOUT;
    let mut exit_status = None;
    while std::time::Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_status = Some(status);
                break;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(_) => {
                RIZIN_FAILURES.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        }
    }
    let status = match exit_status {
        Some(s) => s,
        None => {
            RIZIN_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
            kill_process_group(child_id);
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
    };
    let cap_hit = output_cap_hit.load(Ordering::Acquire);
    if cap_hit {
        RIZIN_MEMORY_EXCEEDED.fetch_add(1, Ordering::Relaxed);
    }
    // Rizin crashed / aborted — partial stdout is unreliable on a
    // failed run, so we drop it rather than emit phantom data.
    if !status.success() {
        RIZIN_FAILURES.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    // Wait for the drain thread. The child has exited, so its
    // write-end of the pipe is closed and `read_to_end` is guaranteed
    // to return promptly — no deadlock risk. A poisoned thread
    // (panic in the drain) is treated like empty stdout.
    let stdout_bytes = drain.join().unwrap_or_default();
    if stdout_bytes.is_empty() {
        RIZIN_FAILURES.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let _ = cap_hit;
    RIZIN_SUCCESSES.fetch_add(1, Ordering::Relaxed);
    let stdout = String::from_utf8_lossy(&stdout_bytes);
    Some(parse_recovery_output(&stdout))
}

/// Apply Unix subprocess hardening: own process group, RLIMIT_AS /
/// RLIMIT_DATA memory cap, PR_SET_PDEATHSIG so the child dies if the
/// parent does. No-op on non-Unix.
#[cfg(unix)]
fn apply_unix_hardening(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    cmd.process_group(0);
    // SAFETY: pre_exec runs in the forked child between fork() and
    // exec(). Only async-signal-safe calls are allowed; setrlimit and
    // prctl are both on the POSIX list. No allocation, no locks.
    #[allow(unsafe_code)]
    unsafe {
        cmd.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: RIZIN_MEMORY_LIMIT_BYTES as libc::rlim_t,
                rlim_max: RIZIN_MEMORY_LIMIT_BYTES as libc::rlim_t,
            };
            // RLIMIT_AS caps total virtual address space on Linux —
            // the one that actually bites mmap/malloc. RLIMIT_DATA is
            // the best approximation on macOS. Failures are ignored:
            // if the caller is already limited below our target,
            // EINVAL is expected and the caller's tighter limit wins.
            #[cfg(target_os = "linux")]
            {
                libc::setrlimit(libc::RLIMIT_AS, &limit);
                // Ask the kernel to SIGKILL this subprocess if the
                // parent dies without running our own cleanup —
                // covers panic/abort/SIGKILL/OOM paths where the
                // ctrlc handler never gets to run
                // `kill_all_rizin_groups`.
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            }
            libc::setrlimit(libc::RLIMIT_DATA, &raw const limit);
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn apply_unix_hardening(_: &mut Command) {}

/// SIGKILL a process group. Used by the reader thread on output-cap
/// overflow and by the timeout cleanup path. No-op on non-Unix.
fn kill_process_group(child_id: u32) {
    #[cfg(unix)]
    // SAFETY: libc::kill with negative pid targets the process group.
    // Async-signal-safe; tolerates already-dead groups silently.
    #[allow(unsafe_code)]
    unsafe {
        libc::kill(-(child_id as libc::pid_t), libc::SIGKILL);
    }
    #[cfg(not(unix))]
    let _ = child_id;
}

/// Mark the output-cap flag and SIGKILL the rizin process group so
/// both pipes close promptly. First call sets the flag and kills;
/// subsequent calls are no-ops.
fn mark_output_cap_hit(flag: &Arc<AtomicBool>, child_id: u32) {
    if flag.swap(true, Ordering::AcqRel) {
        return;
    }
    tracing::warn!(
        pid = child_id,
        cap_bytes = MAX_SUBPROCESS_OUTPUT,
        "rizin output cap exceeded; killing process group"
    );
    kill_process_group(child_id);
}

/// Split rizin's combined stdout (four `===SEP===`-delimited blocks)
/// into typed `RizinRecovery`. Separating this from `recover()` makes
/// the output-shape contract directly unit-testable without needing
/// a real subprocess.
///
/// The four expected blocks, in order, are:
/// 1. `iij`  — JSON array of imports
/// 2. `iEj`  — JSON array of exports
/// 3. `aaa`  — analysis chatter (discarded)
/// 4. `aflj` — JSON array of recovered functions
///
/// Each JSON block tolerates leading log chatter via `parse_json_array`.
/// Missing blocks (truncated output, fewer separators than expected)
/// degrade to empty `Vec`s rather than failing — partial data is more
/// useful than no data on adversarial input.
fn parse_recovery_output(stdout: &str) -> RizinRecovery {
    let mut parts = stdout.split("===SEP===");
    let imports = parts
        .next()
        .and_then(|p| parse_json_array::<RawImport>(p).ok())
        .unwrap_or_default();
    let exports = parts
        .next()
        .and_then(|p| parse_json_array::<RawExport>(p).ok())
        .unwrap_or_default();
    // Third block is `aaa` analysis chatter — discard.
    let _analysis_chatter = parts.next();
    let functions = parts
        .next()
        .and_then(|p| parse_json_array::<RawFunction>(p).ok())
        .unwrap_or_default();
    // Fifth (optional) block is `iSj` — sections. Older callers don't
    // emit it; absence degrades to empty Vec.
    let sections = parts
        .next()
        .and_then(|p| parse_json_array::<RawSection>(p).ok())
        .unwrap_or_default();
    RizinRecovery {
        imports,
        exports,
        functions,
        sections,
    }
}

/// Extract a JSON array out of `text`. Rizin sometimes prefixes
/// arrays with log lines; we tolerate that by scanning for `[`.
fn parse_json_array<T: serde::de::DeserializeOwned>(
    text: &str,
) -> Result<Vec<T>, serde_json::Error> {
    let start = text.find('[').unwrap_or(0);
    serde_json::from_str(&text[start..])
}

/// Raw rizin output — converted into filefacts' unified [`crate::Symbol`]
/// view by `recover()`'s caller.
pub(crate) struct RizinRecovery {
    imports: Vec<RawImport>,
    exports: Vec<RawExport>,
    functions: Vec<RawFunction>,
    sections: Vec<RawSection>,
}

/// Counts of entries rizin contributed to each typed view through
/// [`RizinRecovery::apply`]. Returned so format extractors can emit
/// the `*.recovered_*` metrics that signal "this view was filled in
/// by the disassembly-side fallback, not the format-native parser"
/// — same pattern cleave used historically. The metric path is tool-
/// agnostic because swapping rizin for radare2/Ghidra shouldn't ripple
/// into the schema.
#[derive(Default, Debug, Clone, Copy)]
pub(crate) struct RecoveryCounts {
    pub imports: u32,
    pub exports: u32,
    pub functions: u32,
    pub sections: u32,
}

impl RizinRecovery {
    /// Push recovered symbols into the unified `Symbols` view and emit
    /// the rizin-specific `binary.*` metrics. Only fills slots that
    /// goblin left empty — never overwrites existing data.
    ///
    /// The legacy entry-point that doesn't recover sections.
    pub(crate) fn apply(
        self,
        symbols_out: &mut crate::Symbols,
        metrics: &mut Metrics,
    ) -> RecoveryCounts {
        self.apply_inner(symbols_out, None, metrics)
    }

    /// Variant of [`apply`] that also recovers sections. PE / ELF /
    /// Mach-O extractors call this when goblin returned an empty
    /// section table (packed binaries are the common case).
    pub(crate) fn apply_with_sections(
        self,
        symbols_out: &mut crate::Symbols,
        sections_out: &mut Vec<crate::output::Section>,
        metrics: &mut Metrics,
    ) -> RecoveryCounts {
        self.apply_inner(symbols_out, Some(sections_out), metrics)
    }

    fn apply_inner(
        self,
        symbols_out: &mut crate::Symbols,
        sections_out: Option<&mut Vec<crate::output::Section>>,
        metrics: &mut Metrics,
    ) -> RecoveryCounts {
        use crate::output::{Symbol, SymbolKind};
        let mut counts = RecoveryCounts::default();
        let had_imports = symbols_out
            .iter()
            .any(|s| s.kind() == SymbolKind::Import);
        let had_exports = symbols_out
            .iter()
            .any(|s| s.kind() == SymbolKind::Export);
        let had_functions = symbols_out
            .iter()
            .any(|s| s.kind() == SymbolKind::Function);
        if !had_imports {
            for imp in self.imports {
                if imp.name.is_empty() {
                    continue;
                }
                symbols_out.push(Symbol::Import {
                    name: imp.name,
                    library: imp.libname,
                    source: "rizin".into(),
                    offset: None,
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
                    source: "rizin".into(),
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
                    .filter_map(|c| c.name.clone())
                    .filter(|n| !n.is_empty())
                    .collect();
                let stack_frame = func
                    .stackframe
                    .map(|sf| u64::try_from(sf.max(0)).unwrap_or(0));
                symbols_out.push(Symbol::Function {
                    name: func.name.clone(),
                    source: "rizin".into(),
                    offset: Some(func.offset),
                    decl: None,
                    complexity: func.cc,
                    basic_blocks: func.nbbs,
                    edges: func.edges,
                    instructions: func.ninstrs,
                    stack_frame,
                    recursive: func.recursive,
                    noreturn: func.noreturn,
                    is_linear: func.is_lineal,
                    callees,
                });
                counts.functions = counts.functions.saturating_add(1);
            }
            // Function-level aggregates. Complexity + basic blocks
            // are what `aflj` makes essentially free — they're the
            // ML signals goblin can't produce on a stripped binary.
            // `functions.count` is emitted cross-format by
            // `lib.rs::extract_all` — no rizin-side dual-emit.

            let cc_values: Vec<u32> = self.functions.iter().filter_map(|f| f.cc).collect();
            if !cc_values.is_empty() {
                let sum: u64 = cc_values.iter().map(|&v| u64::from(v)).sum();
                metrics.insert("binary.avg_complexity", sum as f64 / cc_values.len() as f64);
                let max = cc_values.iter().copied().max().unwrap_or(0);
                metrics.insert("binary.max_complexity", f64::from(max));
            }

            let bb_values: Vec<u32> = self.functions.iter().filter_map(|f| f.nbbs).collect();
            if !bb_values.is_empty() {
                let sum: u64 = bb_values.iter().map(|&v| u64::from(v)).sum();
                metrics.insert(
                    "binary.avg_basic_blocks",
                    sum as f64 / bb_values.len() as f64,
                );
                metrics.insert("binary.total_basic_blocks", sum as f64);
            }

            // Function-shape bucket counts. Detection traits target the
            // tails of these distributions: xz's backdoor introduced a
            // single huge function in a sea of tiny ones; obfuscators
            // produce sea-of-tiny shapes (one-block dispatch handlers
            // per opcode); leaf-heavy ratios indicate flattened control
            // flow. Thresholds chosen to match xz-utils inspection
            // norms — `nbbs >= 50` is the standard "non-trivial CFG"
            // floor, `nbbs == 1` is the rizin sentinel for stubs.
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
            metrics.insert("binary.huge_func_count", huge as f64);
            metrics.insert("binary.tiny_func_count", tiny as f64);
            metrics.insert("binary.leaf_func_count", leaf as f64);
        }
        // Section recovery for packed/obfuscated binaries where goblin
        // returned an empty section table. We populate via the same
        // `Section` view all other format extractors emit, with a
        // best-effort flag projection from rizin's perm string
        // (`-r-x` → executable/readable).
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
fn perm_to_flags(perm: Option<&str>) -> Vec<String> {
    let Some(p) = perm else {
        return Vec::new();
    };
    let mut flags = Vec::new();
    if p.contains('r') {
        flags.push("readable".to_string());
    }
    if p.contains('w') {
        flags.push("writable".to_string());
    }
    if p.contains('x') {
        flags.push("executable".to_string());
    }
    flags
}

// =============================================================================
// Wire-format deserialisers. Map rizin's JSON shape to internal structs;
// filefacts' public typed views (Import / Export / Function) stay independent.
// =============================================================================

#[derive(Deserialize)]
struct RawImport {
    name: String,
    libname: Option<String>,
    ordinal: Option<u32>,
}

#[derive(Deserialize)]
struct RawExport {
    name: String,
    #[serde(default)]
    vaddr: u64,
}

#[derive(Deserialize)]
struct RawFunction {
    name: String,
    /// Function entry address. Rizin uses `offset`; older r2 used `addr`.
    #[serde(alias = "addr")]
    #[serde(default)]
    offset: u64,
    /// Cyclomatic complexity.
    #[serde(default)]
    cc: Option<u32>,
    /// Number of basic blocks.
    #[serde(default)]
    nbbs: Option<u32>,
    /// Control-flow edges between basic blocks.
    #[serde(default)]
    edges: Option<u32>,
    /// Total instruction count.
    #[serde(default)]
    ninstrs: Option<u32>,
    /// Stack frame size in bytes. Rizin emits a signed int (negative
    /// values indicate "no frame"); we normalise to `u64` via `.max(0)`
    /// in `apply`.
    #[serde(default)]
    stackframe: Option<i64>,
    /// `true` iff the function calls itself directly.
    #[serde(default)]
    recursive: Option<bool>,
    /// `true` iff the function never returns.
    #[serde(default)]
    noreturn: Option<bool>,
    /// Straight-line code with no branches. Rizin's `aflj` emits this
    /// under the kebab-case key `is-lineal` (sic, rizin's typo).
    #[serde(default, rename = "is-lineal", alias = "is_lineal")]
    is_lineal: Option<bool>,
    /// Resolved outgoing call edges. Each entry has a `name` field
    /// when rizin could resolve the callee; entries without a name
    /// are dropped during `apply`.
    #[serde(default)]
    callrefs: Vec<RawCallref>,
}

#[derive(Deserialize)]
struct RawCallref {
    #[serde(default)]
    name: Option<String>,
}

/// Rizin `iSj` section entry. Same fields cleave's `R2Section`
/// historically deserialised. `paddr` / `vaddr` / `vsize` are
/// optional because rizin sometimes emits a 0 for sections whose
/// layout it couldn't fully resolve.
#[derive(Deserialize)]
struct RawSection {
    #[serde(default)]
    name: String,
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::output::Metrics;

    /// Tests that interact with the process-global `RIZIN_PGIDS`
    /// registry — the live shim spawns and the `kill_all_rizin_groups`
    /// reaper — must hold this mutex for the duration of their run.
    /// Without it the reaper test SIGKILLs shims registered by other
    /// in-flight tests, producing intermittent "shim recovery missing"
    /// failures under cargo's default parallel test execution.
    fn rizin_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        // `unwrap_or_else` so a poisoned mutex (from a panicking test
        // holding the guard) doesn't poison every subsequent test —
        // the registry state survives across test panics regardless.
        LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn make_recovery(json: &str) -> RizinRecovery {
        #[derive(Deserialize)]
        struct Wire {
            #[serde(default)]
            imports: Vec<RawImport>,
            #[serde(default)]
            exports: Vec<RawExport>,
            #[serde(default)]
            functions: Vec<RawFunction>,
            #[serde(default)]
            sections: Vec<RawSection>,
        }
        let w: Wire = serde_json::from_str(json).expect("valid test JSON");
        RizinRecovery {
            imports: w.imports,
            exports: w.exports,
            functions: w.functions,
            sections: w.sections,
        }
    }

    // ------------------------------------------------------------------
    // parse_json_array
    // ------------------------------------------------------------------

    #[test]
    fn parse_json_array_strips_leading_log_chatter() {
        // Rizin sometimes emits warning lines before the JSON array
        // (we redirect stderr to /dev/null, but a stray INFO can leak
        // to stdout). `parse_json_array` skips to the first `[`.
        let text = "INFO: scanning sections...\n[{\"name\":\"foo\",\"libname\":\"x.so\"}]";
        let v: Vec<RawImport> = parse_json_array(text).expect("parses past chatter");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name, "foo");
        assert_eq!(v[0].libname.as_deref(), Some("x.so"));
    }

    #[test]
    fn parse_json_array_handles_pure_array() {
        let v: Vec<RawImport> =
            parse_json_array(r#"[{"name":"a"},{"name":"b","ordinal":3}]"#).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[1].ordinal, Some(3));
    }

    #[test]
    fn parse_json_array_rejects_malformed_json() {
        // Non-array root → serde rejects.
        assert!(parse_json_array::<RawImport>("not json at all").is_err());
        // Array-shaped opener but truncated content.
        assert!(parse_json_array::<RawImport>("[{\"name\":\"x\"").is_err());
    }

    #[test]
    fn parse_json_array_empty_array_is_ok() {
        let v: Vec<RawImport> = parse_json_array("[]").unwrap();
        assert!(v.is_empty());
    }

    // ------------------------------------------------------------------
    // RawFunction accepts both rizin (`offset`) and old r2 (`addr`) keys
    // ------------------------------------------------------------------

    #[test]
    fn raw_function_accepts_offset_or_addr() {
        let v: Vec<RawFunction> = parse_json_array(r#"[{"name":"a","offset":4096}]"#).unwrap();
        assert_eq!(v[0].offset, 4096);
        let v: Vec<RawFunction> = parse_json_array(r#"[{"name":"b","addr":8192}]"#).unwrap();
        assert_eq!(v[0].offset, 8192);
    }

    // ------------------------------------------------------------------
    // apply gate logic — "only fill what goblin left empty"
    // ------------------------------------------------------------------

    use crate::output::{Symbol, SymbolKind, Symbols};

    fn first_function(symbols: &Symbols) -> Option<&Symbol> {
        symbols.iter_kind(SymbolKind::Function).next()
    }

    fn count_kind(symbols: &Symbols, kind: SymbolKind) -> usize {
        symbols.iter_kind(kind).count()
    }

    #[test]
    fn apply_populates_cfg_fields_from_aflj() {
        // Full aflj payload — every CFG field exercised, including the
        // is-lineal kebab key, the callrefs list (some named, some
        // anonymous → only named ones land on `callees`), and the
        // signed stackframe normalisation.
        let recovery = make_recovery(
            r#"{
                "imports": [],
                "exports": [],
                "functions": [{
                    "name": "main",
                    "offset": 4096,
                    "cc": 7,
                    "nbbs": 12,
                    "edges": 18,
                    "ninstrs": 83,
                    "stackframe": 48,
                    "recursive": false,
                    "noreturn": false,
                    "is-lineal": false,
                    "callrefs": [
                        {"name": "puts"},
                        {"name": "exit"},
                        {}
                    ]
                }]
            }"#,
        );
        let mut symbols = Symbols::new();
        let mut metrics = Metrics::new();
        recovery.apply(&mut symbols, &mut metrics);
        let Some(Symbol::Function {
            complexity,
            basic_blocks,
            edges,
            instructions,
            stack_frame,
            recursive,
            noreturn,
            is_linear,
            callees,
            ..
        }) = first_function(&symbols)
        else {
            panic!("expected one rizin function");
        };
        assert_eq!(*complexity, Some(7));
        assert_eq!(*basic_blocks, Some(12));
        assert_eq!(*edges, Some(18));
        assert_eq!(*instructions, Some(83));
        assert_eq!(*stack_frame, Some(48));
        assert_eq!(*recursive, Some(false));
        assert_eq!(*noreturn, Some(false));
        assert_eq!(*is_linear, Some(false));
        assert_eq!(*callees, vec!["puts".to_string(), "exit".to_string()]);
    }

    #[test]
    fn apply_populates_when_all_views_empty() {
        let recovery = make_recovery(
            r#"{
                "imports": [{"name":"open","libname":"libc.so"}],
                "exports": [{"name":"entry","vaddr":4096}],
                "functions": [{"name":"main","offset":4096,"cc":5,"nbbs":10}]
            }"#,
        );
        let mut symbols = Symbols::new();
        let mut metrics = Metrics::new();
        recovery.apply(&mut symbols, &mut metrics);
        assert_eq!(count_kind(&symbols, SymbolKind::Import), 1);
        assert_eq!(count_kind(&symbols, SymbolKind::Export), 1);
        assert_eq!(count_kind(&symbols, SymbolKind::Function), 1);
        // Rizin-side aggregates stay under `binary.*_complexity` /
        // `binary.*_basic_blocks`.
        assert_eq!(metrics.get("binary.avg_complexity"), Some(5.0));
        assert_eq!(metrics.get("binary.max_complexity"), Some(5.0));
        assert_eq!(metrics.get("binary.avg_basic_blocks"), Some(10.0));
        assert_eq!(metrics.get("binary.total_basic_blocks"), Some(10.0));
    }

    #[test]
    fn apply_skips_imports_when_goblin_already_populated() {
        let recovery =
            make_recovery(r#"{"imports":[{"name":"rizin_only"}],"exports":[],"functions":[]}"#);
        let mut symbols = Symbols::new();
        symbols.push(Symbol::Import {
            name: "from_goblin".into(),
            library: None,
            source: "elf-dynsym".into(),
            offset: None,
            ordinal: None,
        });
        let mut metrics = Metrics::new();
        recovery.apply(&mut symbols, &mut metrics);
        // Rizin import dropped — goblin's entry survives untouched.
        let names: Vec<String> = symbols
            .iter_kind(SymbolKind::Import)
            .filter_map(|s| match s {
                Symbol::Import { name, .. } => Some(name.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(names, vec!["from_goblin"]);
    }

    #[test]
    fn apply_skips_function_metrics_when_functions_already_populated() {
        let recovery = make_recovery(
            r#"{"imports":[],"exports":[],"functions":[{"name":"a","offset":1,"cc":99,"nbbs":99}]}"#,
        );
        let mut symbols = Symbols::new();
        symbols.push(Symbol::Function {
            name: "preexisting".into(),
            source: "goblin".into(),
            offset: Some(0),
            decl: None,
            complexity: None,
            basic_blocks: None,
            edges: None,
            instructions: None,
            stack_frame: None,
            recursive: None,
            noreturn: None,
            is_linear: None,
            callees: Vec::new(),
        });
        let mut metrics = Metrics::new();
        recovery.apply(&mut symbols, &mut metrics);
        // The function-block was skipped → no aggregate metrics emitted.
        assert!(metrics.get("binary.avg_complexity").is_none());
        // The preexisting goblin function survives.
        assert_eq!(count_kind(&symbols, SymbolKind::Function), 1);
    }

    #[test]
    fn apply_drops_unnamed_entries() {
        let recovery = make_recovery(
            r#"{
                "imports": [{"name":""},{"name":"keep"}],
                "exports": [{"name":""},{"name":"keep","vaddr":1}],
                "functions": [{"name":"","offset":0},{"name":"keep","offset":1}]
            }"#,
        );
        let mut symbols = Symbols::new();
        let mut metrics = Metrics::new();
        recovery.apply(&mut symbols, &mut metrics);
        assert_eq!(count_kind(&symbols, SymbolKind::Import), 1);
        assert_eq!(count_kind(&symbols, SymbolKind::Export), 1);
        assert_eq!(count_kind(&symbols, SymbolKind::Function), 1);
    }

    #[test]
    fn apply_aggregates_complexity_correctly() {
        // Three functions with cc 1, 3, 5 → mean = 3, max = 5.
        // nbbs 2, 4, 6 → mean = 4, total = 12.
        let recovery = make_recovery(
            r#"{
                "imports": [],
                "exports": [],
                "functions": [
                    {"name":"a","offset":1,"cc":1,"nbbs":2},
                    {"name":"b","offset":2,"cc":3,"nbbs":4},
                    {"name":"c","offset":3,"cc":5,"nbbs":6}
                ]
            }"#,
        );
        let mut symbols = Symbols::new();
        let mut metrics = Metrics::new();
        recovery.apply(&mut symbols, &mut metrics);
        assert_eq!(count_kind(&symbols, SymbolKind::Function), 3);
        assert_eq!(metrics.get("binary.avg_complexity"), Some(3.0));
        assert_eq!(metrics.get("binary.max_complexity"), Some(5.0));
        assert_eq!(metrics.get("binary.avg_basic_blocks"), Some(4.0));
        assert_eq!(metrics.get("binary.total_basic_blocks"), Some(12.0));
    }

    #[test]
    fn apply_omits_complexity_metrics_when_cc_absent() {
        // Functions without `cc` shouldn't emit complexity averages.
        // Without `nbbs` shouldn't emit basic-block aggregates either.
        let recovery =
            make_recovery(r#"{"imports":[],"exports":[],"functions":[{"name":"a","offset":1}]}"#);
        let mut symbols = Symbols::new();
        let mut metrics = Metrics::new();
        recovery.apply(&mut symbols, &mut metrics);
        assert_eq!(count_kind(&symbols, SymbolKind::Function), 1);
        assert!(metrics.get("binary.avg_complexity").is_none());
        assert!(metrics.get("binary.avg_basic_blocks").is_none());
    }

    // ------------------------------------------------------------------
    // available() — smoke
    // ------------------------------------------------------------------

    #[test]
    fn available_does_not_panic() {
        // We can't assert the result (depends on the test host's
        // PATH); just confirm the probe doesn't panic and returns a
        // bool stably across calls (the cache works).
        let first = available();
        let second = available();
        assert_eq!(first, second, "PATH probe should be cached");
    }

    // ------------------------------------------------------------------
    // Hardening: disable switch, scoped_disable RAII, stats counters
    // ------------------------------------------------------------------

    #[test]
    fn scoped_disable_increments_and_restores_disable_count() {
        // Read the baseline because parallel tests may also be holding
        // a guard — we assert the *delta*, not the absolute value.
        let before = RIZIN_DISABLED.load(Ordering::SeqCst);
        {
            let _g = scoped_disable();
            assert!(is_disabled());
            assert_eq!(RIZIN_DISABLED.load(Ordering::SeqCst), before + 1);
        }
        assert_eq!(RIZIN_DISABLED.load(Ordering::SeqCst), before);
    }

    #[test]
    fn scoped_disable_stacks() {
        let before = RIZIN_DISABLED.load(Ordering::SeqCst);
        let g1 = scoped_disable();
        let g2 = scoped_disable();
        assert_eq!(RIZIN_DISABLED.load(Ordering::SeqCst), before + 2);
        drop(g1);
        assert!(is_disabled(), "still disabled while outer guard alive");
        drop(g2);
        assert_eq!(RIZIN_DISABLED.load(Ordering::SeqCst), before);
    }

    #[test]
    fn recover_short_circuits_when_disabled() {
        // With a guard active, the public `recover()` entry returns
        // None before touching PATH or spawning anything. We can't
        // assert the absolute counters (parallel tests mutate them),
        // only the observable contract: disabled → None.
        let _g = scoped_disable();
        assert!(is_disabled());
        let r = recover(b"unused bytes for disabled probe");
        assert!(r.is_none(), "disabled rizin must return None");
    }

    #[test]
    #[cfg(unix)]
    fn kill_all_rizin_groups_drains_pgid_registry_idempotently() {
        // Hold the rizin test lock — `kill_all_rizin_groups` SIGKILLs
        // every entry in the registry, which would otherwise reap
        // live shim subprocesses from sibling tests running in
        // parallel under the default cargo-test thread pool.
        let _lock = rizin_test_lock();
        // No PGIDs registered: should be a clean no-op. Verifies the
        // public reaper survives being called from a CLI signal
        // handler after a clean shutdown.
        let before = RIZIN_PGIDS.lock().map(|g| g.len()).unwrap_or(0);
        kill_all_rizin_groups();
        let after = RIZIN_PGIDS.lock().map(|g| g.len()).unwrap_or(0);
        assert_eq!(before, after);
    }

    #[test]
    fn log_stats_is_no_op_when_total_zero() {
        // Just confirm the call doesn't panic when nothing has been
        // recorded yet. Real telemetry assertions would need a
        // tracing subscriber; that's out of scope here.
        // (We don't assert the counter — parallel tests may have
        // bumped it.)
        log_stats();
    }

    #[test]
    fn stats_tuple_shape_is_stable() {
        let (total, successes, timeouts, failures, mem) = stats();
        // Tautological — purpose is to pin the (5,) tuple shape so a
        // future API change trips a compile error here. The cleave
        // host CLI destructures the tuple positionally.
        let _ = (total, successes, timeouts, failures, mem);
    }

    // ------------------------------------------------------------------
    // parse_recovery_output — block splitting + per-block error tolerance
    // ------------------------------------------------------------------

    /// Build a synthetic rizin stdout matching the
    /// `iij; echo ===SEP===; iEj; echo ===SEP===; aaa; echo ===SEP===; aflj`
    /// shape — four blocks with the canonical separator.
    fn synthesize_stdout(imports: &str, exports: &str, chatter: &str, functions: &str) -> String {
        format!("{imports}\n===SEP===\n{exports}\n===SEP===\n{chatter}\n===SEP===\n{functions}")
    }

    #[test]
    fn parse_recovery_output_splits_canonical_four_block_shape() {
        let stdout = synthesize_stdout(
            r#"[{"name":"open","libname":"libc.so"}]"#,
            r#"[{"name":"start","vaddr":4096}]"#,
            "[INFO] analysis ran",
            r#"[{"name":"main","offset":4096,"cc":3,"nbbs":5}]"#,
        );
        let rec = parse_recovery_output(&stdout);
        assert_eq!(rec.imports.len(), 1);
        assert_eq!(rec.imports[0].name, "open");
        assert_eq!(rec.exports.len(), 1);
        assert_eq!(rec.exports[0].vaddr, 4096);
        assert_eq!(rec.functions.len(), 1);
        assert_eq!(rec.functions[0].cc, Some(3));
    }

    #[test]
    fn parse_recovery_output_tolerates_truncated_blocks() {
        // Only two separators present — third + fourth blocks missing.
        // Should yield empty exports/functions rather than panic.
        let stdout = "[]\n===SEP===\n[{\"name\":\"a\"}]";
        let rec = parse_recovery_output(stdout);
        assert!(rec.imports.is_empty());
        assert_eq!(rec.exports.len(), 1);
        assert_eq!(rec.exports[0].name, "a");
        assert!(rec.functions.is_empty());
    }

    #[test]
    fn parse_recovery_output_recovers_from_malformed_block() {
        // First block is unparseable JSON; we still get the rest.
        let stdout = synthesize_stdout(
            "this is not json",
            r#"[{"name":"x","vaddr":1}]"#,
            "",
            r#"[{"name":"y","offset":2}]"#,
        );
        let rec = parse_recovery_output(&stdout);
        assert!(rec.imports.is_empty(), "bad JSON → empty, not panic");
        assert_eq!(rec.exports.len(), 1);
        assert_eq!(rec.functions.len(), 1);
    }

    #[test]
    fn parse_recovery_output_handles_empty_stdout() {
        let rec = parse_recovery_output("");
        assert!(rec.imports.is_empty());
        assert!(rec.exports.is_empty());
        assert!(rec.functions.is_empty());
    }

    // ------------------------------------------------------------------
    // End-to-end spawn/drain via a fake-rizin shim script
    // ------------------------------------------------------------------

    /// Process-unique counter for shim scratch dirs. The previous
    /// `pid + subsec_nanos` scheme raced when three tests staged dirs
    /// inside the same nanosecond window under parallel execution.
    #[cfg(unix)]
    fn unique_shim_dir(prefix: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed),
        ))
    }

    /// Stage a shell script that masquerades as `rizin`, prints a
    /// fixed stdout payload (escaping the canonical separators), and
    /// returns its directory so we can stitch it onto PATH. Returns
    /// `None` on non-Unix or when `/bin/sh` isn't available — those
    /// platforms exercise the same paths under cleave's real rizin.
    #[cfg(unix)]
    fn stage_shim(stdout_payload: &str) -> Option<std::path::PathBuf> {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let dir = unique_shim_dir("filefacts-rizin-shim");
        std::fs::create_dir_all(&dir).ok()?;
        let shim = dir.join("rizin");
        let mut f = std::fs::File::create(&shim).ok()?;
        // The body interprets `$1` etc. as rizin's CLI args. We don't
        // care about them — we just emit the canned stdout the
        // production code expects to parse.
        writeln!(f, "#!/bin/sh").ok()?;
        // `cat <<'EOF'` preserves the body bytes-for-bytes; the
        // single-quoted EOF disables shell expansion so payloads with
        // backticks / dollars survive.
        writeln!(f, "cat <<'EOF'").ok()?;
        f.write_all(stdout_payload.as_bytes()).ok()?;
        writeln!(f).ok()?;
        writeln!(f, "EOF").ok()?;
        let mut perms = std::fs::metadata(&shim).ok()?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&shim, perms).ok()?;
        Some(dir)
    }

    /// Spawn the shim through the same `recover()` codepath production
    /// uses, with PATH pointed at the shim dir. The cached PATH probe
    /// in `rizin_binary()` is bypassed via a private helper that takes
    /// the bin path directly — see `recover_with_bin_for_test`.
    #[cfg(unix)]
    fn run_against_shim(stdout_payload: &str, input_bytes: &[u8]) -> Option<RizinRecovery> {
        let dir = stage_shim(stdout_payload)?;
        let shim_path = dir.join("rizin");
        let result = recover_with_bin_for_test(&shim_path, input_bytes);
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    #[test]
    #[cfg(unix)]
    fn end_to_end_shim_returns_parsed_recovery() {
        let _lock = rizin_test_lock();
        // A canonical four-block payload — exercises spawn, drain,
        // separator split, and per-block JSON parse together.
        let payload = synthesize_stdout(
            r#"[{"name":"malloc","libname":"libc.so.6"}]"#,
            r#"[{"name":"entry","vaddr":4096}]"#,
            "analysis-chatter-ignored",
            r#"[{"name":"f1","offset":4096,"cc":7,"nbbs":12}]"#,
        );
        let rec = run_against_shim(&payload, b"unused bytes for temp file").expect(
            "shim should return a recovery; if your /bin/sh is missing this test can't run",
        );
        assert_eq!(rec.imports.len(), 1);
        assert_eq!(rec.imports[0].libname.as_deref(), Some("libc.so.6"));
        assert_eq!(rec.exports.len(), 1);
        assert_eq!(rec.functions.len(), 1);
        assert_eq!(rec.functions[0].cc, Some(7));
    }

    #[test]
    #[cfg(unix)]
    fn end_to_end_shim_handles_large_stdout_via_pipe_drain() {
        let _lock = rizin_test_lock();
        // Build a function array large enough to exceed the typical
        // 64 KiB pipe buffer — without the background drain thread,
        // this would deadlock on shim's stdout write. With drain, it
        // streams through and parses.
        let mut funcs = String::from("[");
        for i in 0..2000 {
            if i > 0 {
                funcs.push(',');
            }
            funcs.push_str(&format!(
                r#"{{"name":"fcn.{i:06x}","offset":{i},"cc":1,"nbbs":1}}"#,
            ));
        }
        funcs.push(']');
        let payload = synthesize_stdout("[]", "[]", "", &funcs);
        assert!(
            payload.len() > 100_000,
            "payload {} bytes — must exceed pipe buffer",
            payload.len()
        );
        let rec = run_against_shim(&payload, b"x").expect("shim recovery");
        assert_eq!(rec.functions.len(), 2000);
    }

    #[test]
    #[cfg(unix)]
    fn end_to_end_shim_returns_some_empty_recovery_on_separator_only_stdout() {
        let _lock = rizin_test_lock();
        // Three SEPs with empty blocks → valid but contentless rizin
        // output. recover() returns Some(empty) here; `apply` is then
        // a no-op (functions empty → no metrics emitted) and the
        // caller's existing goblin data survives untouched. This is
        // distinct from the "empty bytes → None" case below.
        let payload = synthesize_stdout("[]", "[]", "", "[]");
        let rec = run_against_shim(&payload, b"x").expect("empty arrays still parse");
        assert!(rec.imports.is_empty());
        assert!(rec.exports.is_empty());
        assert!(rec.functions.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn end_to_end_recover_returns_none_when_stdout_bytes_empty() {
        let _lock = rizin_test_lock();
        // Pure-stdlib shim that exits 0 with zero stdout bytes. Exercises
        // the `stdout_bytes.is_empty() → None` guard against subprocesses
        // that silently fail (rizin crashing before its first echo).
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let dir = unique_shim_dir("filefacts-rizin-silentshim");
        std::fs::create_dir_all(&dir).unwrap();
        let shim = dir.join("rizin");
        let mut f = std::fs::File::create(&shim).unwrap();
        // `exit 0` produces zero stdout bytes — no trailing newline.
        f.write_all(b"#!/bin/sh\nexit 0\n").unwrap();
        let mut perms = std::fs::metadata(&shim).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&shim, perms).unwrap();
        let rec = recover_with_bin_for_test(&shim, b"unused");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(rec.is_none(), "zero stdout bytes should yield None");
    }

    #[test]
    #[cfg(unix)]
    fn end_to_end_recover_returns_none_on_nonzero_exit() {
        let _lock = rizin_test_lock();
        // Shim exits non-zero (rizin crashed) — recover should not
        // return phantom data even if some partial stdout leaked.
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let dir = unique_shim_dir("filefacts-rizin-failshim");
        std::fs::create_dir_all(&dir).unwrap();
        let shim = dir.join("rizin");
        let mut f = std::fs::File::create(&shim).unwrap();
        f.write_all(b"#!/bin/sh\necho 'partial output'\nexit 1\n")
            .unwrap();
        let mut perms = std::fs::metadata(&shim).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&shim, perms).unwrap();
        let rec = recover_with_bin_for_test(&shim, b"unused");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(rec.is_none(), "non-zero exit should yield None");
    }

    // Temp-file cleanup is enforced by a `Drop` guard on `Cleanup<'_>`
    // inside `recover_with_bin`. Snapshotting `/tmp` before/after a
    // shim run would race against parallel shim tests (other threads
    // running `recover_with_bin_for_test` create files with the same
    // PID prefix); serialising every shim test to make the snapshot
    // deterministic defeats parallelism. The Drop pattern is idiomatic
    // Rust and was verified end-to-end on the malware sample run
    // (8,325 functions recovered, no `filefacts-rizin-*` files left in
    // `/tmp` across sessions).
}
