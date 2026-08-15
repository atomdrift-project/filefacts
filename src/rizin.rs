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

use std::cell::Cell;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use serde::Deserialize;

use crate::output::Metrics;

/// Default hard cap on a single Rizin run. `aaa` analysis on a heavily
/// stripped ~14 MB Linux binary needed ~85 s in real measurement, while large
/// but legitimate native images can take several minutes. Ten minutes gives
/// those a useful completion window without letting a pathological subprocess
/// occupy an analysis worker indefinitely.
pub const DEFAULT_RIZIN_TIMEOUT_SECS: u64 = 600;
const RIZIN_TIMEOUT: Duration = Duration::from_secs(DEFAULT_RIZIN_TIMEOUT_SECS);

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

/// Full analysis plus the four JSON tables imported by [`RizinRecovery`].
const RIZIN_METRICS_SCRIPT: &str =
    "iij; echo ===SEP===; iEj; echo ===SEP===; aaa; echo ===SEP===; aflj; echo ===SEP===; iSj";

/// Rizin switches that remove work whose output filefacts never consumes.
/// Keep this separate from the input path so the contract is directly tested.
const RIZIN_METRICS_ARGS: &[&str] = &[
    "-NN",
    "-q",
    "-T",
    "-z",
    "-e",
    "scr.color=0",
    "-e",
    "log.level=0",
    "-e",
    "analysis.vars=false",
    "-c",
    RIZIN_METRICS_SCRIPT,
];

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

/// Per-run rizin wall-clock budget, in seconds. `0` selects the [`RIZIN_TIMEOUT`]
/// default. Lowered by latency-sensitive callers (e.g. `ascan ps`, which scans
/// live process binaries where a multi-minute disassembly is never worth it).
static RIZIN_TIMEOUT_SECS: AtomicU64 = AtomicU64::new(0);

/// Skip rizin entirely for inputs larger than this many bytes. `0` disables the
/// gate. Full `aaa` on a 100 MB+ stripped binary costs minutes; a size cap keeps
/// a directory of giant signed apps from dominating a scan.
static RIZIN_MAX_BYTES: AtomicUsize = AtomicUsize::new(0);

/// When set, fat Mach-O inputs are sliced to the host-native architecture before
/// rizin runs, instead of handing rizin the whole universal binary. Cuts the
/// work on multi-arch binaries roughly in half and avoids analysing a slice that
/// will never execute on this host. Off by default (full-fidelity filesystem
/// scans still cover every slice).
static RIZIN_NATIVE_ARCH_ONLY: AtomicBool = AtomicBool::new(false);

/// Set the per-run rizin timeout (seconds). `0` restores the default.
pub fn set_timeout_secs(secs: u64) {
    RIZIN_TIMEOUT_SECS.store(secs, Ordering::Relaxed);
}

/// Resolved rizin timeout: the override when set, else [`RIZIN_TIMEOUT`].
fn rizin_timeout() -> Duration {
    match RIZIN_TIMEOUT_SECS.load(Ordering::Relaxed) {
        0 => RIZIN_TIMEOUT,
        secs => Duration::from_secs(secs),
    }
}

/// Skip rizin for inputs larger than `max_bytes`. `0` disables the gate.
pub fn set_max_bytes(max_bytes: usize) {
    RIZIN_MAX_BYTES.store(max_bytes, Ordering::Relaxed);
}

/// Slice fat Mach-O inputs to the host-native arch before running rizin.
pub fn set_native_arch_only(enabled: bool) {
    RIZIN_NATIVE_ARCH_ONLY.store(enabled, Ordering::Relaxed);
}

/// Whether fat Mach-O inputs should be sliced to the native arch before rizin.
#[must_use]
pub fn native_arch_only() -> bool {
    RIZIN_NATIVE_ARCH_ONLY.load(Ordering::Relaxed)
}

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
#[must_use = "dropping the guard immediately re-enables rizin; bind it to a \
              variable that lives at least as long as the scope you intended to mute"]
pub struct ScopedDisable {
    _private: (),
}

impl Drop for ScopedDisable {
    fn drop(&mut self) {
        RIZIN_DISABLED.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Disable rizin for the lifetime of the returned guard.
///
/// Process-global: every thread sees the mute. That is what a
/// whole-scan policy (`--no-radare2`) wants, since the scan fans out
/// across a thread pool. It is the WRONG tool for a per-file decision —
/// see [`scoped_disable_current_thread`].
pub fn scoped_disable() -> ScopedDisable {
    RIZIN_DISABLED.fetch_add(1, Ordering::SeqCst);
    ScopedDisable { _private: () }
}

thread_local! {
    /// Per-thread mute depth; see [`scoped_disable_current_thread`].
    static RIZIN_DISABLED_THREAD: Cell<usize> = const { Cell::new(0) };
}

/// RAII guard returned by [`scoped_disable_current_thread`]. Restores the
/// calling thread's previous state on drop; guards stack.
#[must_use = "dropping the guard immediately re-enables rizin; bind it to a               variable that lives at least as long as the scope you intended to mute"]
pub struct ScopedDisableThread {
    _private: (),
}

impl Drop for ScopedDisableThread {
    fn drop(&mut self) {
        RIZIN_DISABLED_THREAD.with(|c| c.set(c.get().saturating_sub(1)));
    }
}

/// Disable rizin **on the calling thread only**, for the guard's lifetime.
///
/// Use this to express a per-file policy ("this member is not a native
/// binary, don't disassemble it"). [`scoped_disable`] cannot express that:
/// it mutes the whole process, so while one thread skips disassembly for
/// its own file, every binary being analyzed concurrently on other threads
/// silently loses its symbols and metrics too — the traits derived from
/// them vanish and the verdict shifts, non-deterministically with thread
/// timing. Analyzers fan members out across rayon, so that is not
/// hypothetical.
///
/// Sound because [`recover`] consults [`is_disabled`] synchronously on the
/// thread that requested the parse: filefacts spawns no worker threads
/// between the two (the only spawns are rizin's own stdout drain, after the
/// check, and the unrelated cache sweep).
pub fn scoped_disable_current_thread() -> ScopedDisableThread {
    RIZIN_DISABLED_THREAD.with(|c| c.set(c.get() + 1));
    ScopedDisableThread { _private: () }
}

/// `true` when rizin is muted for the calling thread — by the global
/// [`disable`] / [`scoped_disable`], or by this thread's own
/// [`scoped_disable_current_thread`].
pub fn is_disabled() -> bool {
    RIZIN_DISABLED.load(Ordering::SeqCst) > 0 || RIZIN_DISABLED_THREAD.with(Cell::get) > 0
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

/// rizin's self-reported version string, probed once and cached.
///
/// Used only to invalidate the disk cache across rizin upgrades, so the
/// exact text is opaque — any change that alters analysis output also
/// changes this line. `None` when rizin isn't on PATH or the probe
/// fails. Spawns `rizin -v` a single time per process.
fn rizin_version() -> Option<&'static str> {
    static VERSION: OnceLock<Option<String>> = OnceLock::new();
    VERSION
        .get_or_init(|| {
            let bin = rizin_binary()?;
            let output = Command::new(bin)
                .arg("-v")
                .stdin(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .output()
                .ok()?;
            if !output.status.success() {
                return None;
            }
            let text = String::from_utf8_lossy(&output.stdout);
            let first = text.lines().next().unwrap_or("").trim();
            (!first.is_empty()).then(|| first.to_string())
        })
        .as_deref()
}

/// Cache discriminator capturing the rizin configuration that changes
/// the *correct* recovery for a given input and is stable across runs.
///
/// Folded into the disk-cache key by [`crate::cache::cache_key`] so a
/// payload recovered under one rizin setup is never served to a run with
/// a different one. It captures:
///
/// * whether rizin is on PATH and its version — an upgraded rizin that
///   discovers more functions must not reuse an older run's recovery;
/// * native-arch slicing — a fat Mach-O analysed as a single host slice
///   yields different symbols than the whole universal binary, so the
///   host arch is mixed in while that mode is active.
///
/// Transient conditions (disabled, timeout, output cap, size gate) are
/// deliberately *excluded*: those make a run's payload
/// [`crate::cache::Computed::Transient`] instead of minting a distinct,
/// persisted key.
#[must_use]
pub fn cache_fingerprint() -> String {
    if !available() {
        return "rizin=none".to_string();
    }
    let version = rizin_version().unwrap_or("unknown");
    if native_arch_only() {
        format!(
            "rizin={version}|policy=opaque-v1|native={}",
            std::env::consts::ARCH
        )
    } else {
        format!("rizin={version}|policy=opaque-v1")
    }
}

/// Recover symbol tables + function discovery via rizin. Returns
/// `None` when rizin isn't on PATH or invocation failed; callers
/// fall back to whatever goblin already populated.
///
/// Admission is decided before this function. Every admitted binary gets the
/// same full `aaa` pass, preserving function-count and CFG-complexity quality;
/// callers save time by not spawning Rizin for transparent binaries, rather
/// than silently downgrading the metrics of an admitted one.
///
/// Writes `bytes` to a temp file (rizin reads files from disk, not
/// stdin) and deletes it when done.
pub(crate) fn recover(bytes: &[u8]) -> Option<RizinRecovery> {
    if is_disabled() {
        return None;
    }
    // Size gate: skip rizin for inputs above the configured cap. A 100 MB+
    // stripped binary costs minutes of `aaa`; latency-sensitive callers set a
    // cap so one giant doesn't dominate the scan. Counts as a skip, not a
    // failure — goblin's typed views still stand in.
    let max = RIZIN_MAX_BYTES.load(Ordering::Relaxed);
    if max > 0 && bytes.len() > max {
        tracing::debug!(
            bytes = bytes.len(),
            max,
            "rizin recover: skipped (over size cap)"
        );
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

    // `-NN` disables plugin auto-loading (faster startup, fewer surprises).
    // `-T` skips Rizin's file hashes and `-z` skips its duplicate string-table
    // scan: filefacts computes both independently before this fallback. Local
    // variable/argument recovery is also excluded because none of the imported
    // `aflj` fields use it; function discovery, names/ranges, CFG complexity,
    // basic blocks, and call edges remain part of the full `aaa` pass. Three-run
    // ELF/Mach-O/PE benchmarks found equality in every field consumed below.
    // `-q` quits after the `-c` script and `scr.color=0` strips ANSI escapes.
    let path_str = temp.to_string_lossy();
    // The `aaa` pass is deliberately fixed for admitted binaries; the
    // surrounding `iij`/`iEj`/`aflj`/`iSj` are table reads. The `===SEP===`
    // sentinels must stay 1:1 with the parser's `split` below.
    let mut cmd = Command::new(bin);
    cmd.args(RIZIN_METRICS_ARGS).arg(&*path_str);
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::null());

    apply_unix_hardening(&mut cmd);

    // Per-run timing so binary-heavy archives can be diagnosed at the
    // file granularity (the cumulative `log_stats` line hides which input
    // ate the time). `bytes.len()` identifies the run alongside the
    // caller's own per-member `rizin_mode=enabled` log.
    let started = std::time::Instant::now();
    tracing::debug!(bytes = bytes.len(), "rizin recover: begin");

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
            terminate_child(&mut child, child_id);
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

    // Poll until the configured duration has elapsed. Comparing elapsed time
    // avoids overflowing `Instant` if a caller supplies an intentionally
    // enormous timeout override. Once the child exits, the reader thread's
    // `read_to_end` returns naturally.
    let timeout = rizin_timeout();
    let mut exit_status = None;
    while started.elapsed() < timeout {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_status = Some(status);
                break;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(_) => {
                RIZIN_FAILURES.fetch_add(1, Ordering::Relaxed);
                terminate_child(&mut child, child_id);
                let _ = drain.join();
                return None;
            }
        }
    }
    let status = match exit_status {
        Some(s) => s,
        None => {
            RIZIN_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                bytes = bytes.len(),
                elapsed_ms = started.elapsed().as_millis(),
                "rizin recover: end (timed out)"
            );
            terminate_child(&mut child, child_id);
            // Killing the whole group closes every inherited copy of stdout.
            // Join before returning so a timed-out analysis cannot leave a
            // detached drain thread behind after its Rayon caller is released.
            let _ = drain.join();
            return None;
        }
    };
    // The leader has exited, but a helper process could still hold an inherited
    // stdout descriptor open. Terminate any remaining members of Rizin's private
    // process group before joining, so neither a descendant nor the reader can
    // retain this Rayon caller indefinitely. This is harmless when the group is
    // already empty.
    kill_process_group(child_id);
    // Join on every exit-status path—not only success—so a crashing Rizin cannot
    // leak a detached reader thread.
    let stdout_bytes = drain.join().unwrap_or_default();
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
    if stdout_bytes.is_empty() {
        RIZIN_FAILURES.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let _ = cap_hit;
    RIZIN_SUCCESSES.fetch_add(1, Ordering::Relaxed);
    tracing::debug!(
        bytes = bytes.len(),
        elapsed_ms = started.elapsed().as_millis(),
        stdout_bytes = stdout_bytes.len(),
        "rizin recover: end (ok)"
    );
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

/// Terminate the complete Rizin process group and synchronously reap its
/// leader. The direct `Child::kill` is an idempotent fallback for platforms
/// without Unix process groups and for the narrow race where group creation
/// failed before `exec`.
fn terminate_child(child: &mut std::process::Child, child_id: u32) {
    kill_process_group(child_id);
    let _ = child.kill();
    let _ = child.wait();
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
                    .filter_map(|callref| {
                        callref
                            .name
                            .clone()
                            .or_else(|| function_names.get(&callref.to?).cloned())
                    })
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
                    let target = callref
                        .name
                        .clone()
                        .or_else(|| function_names.get(&callref.to?).cloned());
                    symbols_out.push(Symbol::Call {
                        target,
                        args: Vec::new(),
                        offset: callref.from,
                    });
                }
            }
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
    /// PLT/stub address rizin resolves for the import — the site where the
    /// binary actually calls through to the imported symbol. 0 (the serde
    /// default) means rizin couldn't place it; treated as "no location".
    #[serde(default)]
    plt: u64,
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
    /// Function byte size. Used only for correlating separately recovered
    /// native-code facts with their containing function.
    #[serde(default)]
    size: u64,
    /// Cyclomatic complexity.
    #[serde(default)]
    cc: Option<u32>,
    /// Number of basic blocks (feeds the `binary.*_basic_blocks` aggregates).
    #[serde(default)]
    nbbs: Option<u32>,
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

    #[test]
    fn metrics_command_skips_unused_work_but_keeps_full_cfg_analysis() {
        assert!(RIZIN_METRICS_ARGS.contains(&"-T"));
        assert!(RIZIN_METRICS_ARGS.contains(&"-z"));
        assert!(
            RIZIN_METRICS_ARGS
                .windows(2)
                .any(|pair| pair == ["-e", "analysis.vars=false"])
        );
        assert!(
            RIZIN_METRICS_SCRIPT.contains("aaa"),
            "admitted binaries need the full CFG pass"
        );
        for table in ["iij", "iEj", "aflj", "iSj"] {
            assert!(
                RIZIN_METRICS_SCRIPT.contains(table),
                "missing consumed table {table}"
            );
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
        let v: Vec<RawFunction> =
            parse_json_array(r#"[{"name":"a","offset":4096,"size":32}]"#).unwrap();
        assert_eq!(v[0].offset, 4096);
        assert_eq!(v[0].size, 32);
        let v: Vec<RawFunction> = parse_json_array(r#"[{"name":"b","addr":8192}]"#).unwrap();
        assert_eq!(v[0].offset, 8192);
        assert_eq!(v[0].size, 0);
    }

    #[test]
    fn exposes_function_ranges_and_direct_call_edges() {
        let recovery = make_recovery(
            r#"{
                "functions": [
                    {
                        "name": "caller",
                        "offset": 4096,
                        "size": 64,
                        "callrefs": [
                            {"from": 4100, "to": 8192, "type": "CALL"},
                            {"from": 4105, "to": 4098, "type": "CODE"}
                        ]
                    },
                    {"name": "callee", "offset": 8192, "size": 24}
                ]
            }"#,
        );
        assert_eq!(recovery.function_ranges(), vec![(4096, 64), (8192, 24)]);
        assert_eq!(recovery.direct_call_edges(), vec![(4096, 4100, 8192)]);
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
                        {"name": "puts", "from": 4100, "to": 8192, "type": "CALL"},
                        {"name": "exit", "from": 4105, "to": 12288, "type": "CALL"},
                        {"from": 4110, "to": 4098, "type": "CODE"}
                    ]
                }]
            }"#,
        );
        let mut symbols = Symbols::new();
        let mut metrics = Metrics::new();
        recovery.apply(&mut symbols, &mut metrics);
        let Some(Symbol::Function {
            complexity,
            callees,
            ..
        }) = first_function(&symbols)
        else {
            panic!("expected one rizin function");
        };
        assert_eq!(*complexity, Some(7));
        assert_eq!(*callees, vec!["puts".to_string(), "exit".to_string()]);
        assert_eq!(count_kind(&symbols, SymbolKind::Call), 2);
        let calls: Vec<_> = symbols.iter_kind(SymbolKind::Call).collect();
        assert!(matches!(
            calls[0],
            Symbol::Call {
                target: Some(target),
                offset: Some(4100),
                ..
            } if target == "puts"
        ));
        assert!(matches!(
            calls[1],
            Symbol::Call {
                target: Some(target),
                offset: Some(4105),
                ..
            } if target == "exit"
        ));
    }

    #[test]
    fn apply_resolves_anonymous_binary_callrefs_by_target_address() {
        let recovery = make_recovery(
            r#"{
                "functions": [
                    {
                        "name": "entry0",
                        "offset": 4096,
                        "callrefs": [
                            {"from": 4100, "to": 8192, "type": "CALL"},
                            {"from": 4105, "to": 4098, "type": "CODE"}
                        ]
                    },
                    {
                        "name": "fcn.00002000",
                        "offset": 8192
                    }
                ]
            }"#,
        );
        let mut symbols = Symbols::new();
        let mut metrics = Metrics::new();
        recovery.apply(&mut symbols, &mut metrics);

        let calls: Vec<_> = symbols.iter_kind(SymbolKind::Call).collect();
        assert_eq!(calls.len(), 1);
        assert!(matches!(
            calls[0],
            Symbol::Call {
                target: Some(target),
                offset: Some(4100),
                ..
            } if target == "fcn.00002000"
        ));
        let entry = symbols
            .iter_kind(SymbolKind::Function)
            .find(|symbol| symbol.name() == Some("entry0"))
            .expect("entry function");
        assert!(matches!(
            entry,
            Symbol::Function { callees, .. } if callees == &["fcn.00002000".to_string()]
        ));
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
            alias: None,
            library: None,
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
    fn recovered_import_anchors_at_plt_address() {
        // rizin's iij carries the PLT/stub address; recovery records it as the
        // import's offset (it only runs when goblin found zero imports). An
        // import without a plt stays unanchored rather than anchoring at 0.
        let recovery = make_recovery(
            r#"{"imports":[{"name":"dlopen","plt":4096},{"name":"getpid"}],"exports":[],"functions":[]}"#,
        );
        let mut symbols = Symbols::new();
        let mut metrics = Metrics::new();
        recovery.apply(&mut symbols, &mut metrics);
        let offsets: Vec<(String, Option<u64>)> = symbols
            .iter_kind(SymbolKind::Import)
            .filter_map(|s| match s {
                Symbol::Import { name, offset, .. } => Some((name.clone(), *offset)),
                _ => None,
            })
            .collect();
        assert_eq!(
            offsets,
            vec![
                ("dlopen".to_string(), Some(4096)),
                ("getpid".to_string(), None),
            ]
        );
    }

    #[test]
    fn apply_skips_function_metrics_when_functions_already_populated() {
        let recovery = make_recovery(
            r#"{"imports":[],"exports":[],"functions":[{"name":"a","offset":1,"cc":99,"nbbs":99}]}"#,
        );
        let mut symbols = Symbols::new();
        symbols.push(Symbol::Function {
            name: "preexisting".into(),
            offset: Some(0),
            complexity: None,
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

    #[test]
    fn cache_fingerprint_is_stable_and_tracks_availability() {
        // Host-independent contract: the fingerprint is deterministic
        // within a process and reflects whether rizin is on PATH. When
        // absent it is the sentinel `rizin=none`; when present it names a
        // version (or `unknown`), so a no-rizin run and a rizin run never
        // collide on a cache key.
        let first = cache_fingerprint();
        let second = cache_fingerprint();
        assert_eq!(first, second, "fingerprint must be stable per process");
        assert!(first.starts_with("rizin="), "fingerprint names the tool");
        if available() {
            assert_ne!(first, "rizin=none");
        } else {
            assert_eq!(first, "rizin=none");
        }
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

    /// A per-thread mute must not leak to other threads: that is the bug
    /// where one archive member skipping disassembly silently stripped
    /// symbols from a binary being analyzed concurrently.
    #[test]
    fn thread_local_disable_does_not_leak_across_threads() {
        let guard = scoped_disable_current_thread();
        assert!(is_disabled(), "muted on the thread that asked");
        let other = std::thread::spawn(is_disabled).join().unwrap();
        assert!(!other, "must NOT be muted on an unrelated thread");
        drop(guard);
        assert!(!is_disabled(), "restored on drop");
    }

    /// The global switch still covers every thread — `--no-radare2` applies
    /// to a whole scan, which fans out across a pool.
    #[test]
    fn global_disable_still_applies_to_other_threads() {
        let _lock = rizin_test_lock();
        let guard = scoped_disable();
        let other = std::thread::spawn(is_disabled).join().unwrap();
        assert!(other, "global mute must reach other threads");
        drop(guard);
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

    #[test]
    #[cfg(unix)]
    fn exited_rizin_cannot_leave_descendant_holding_worker() {
        let _lock = rizin_test_lock();

        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let dir = unique_shim_dir("filefacts-rizin-descendantshim");
        std::fs::create_dir_all(&dir).unwrap();
        let shim = dir.join("rizin");
        let descendant_pid = dir.join("descendant.pid");
        let mut f = std::fs::File::create(&shim).unwrap();
        writeln!(f, "#!/bin/sh").unwrap();
        // The descendant inherits stdout, then the shim exits immediately. If
        // the recovery path only reaps the group leader, `drain.join()` blocks
        // until this sleep ends and retains its Rayon caller in the meantime.
        writeln!(f, "sleep 5 &").unwrap();
        writeln!(f, "descendant=$!").unwrap();
        writeln!(
            f,
            "printf '%s\\n' \"$descendant\" > '{}'",
            descendant_pid.display()
        )
        .unwrap();
        writeln!(f, "exit 1").unwrap();
        let mut perms = std::fs::metadata(&shim).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&shim, perms).unwrap();
        drop(f);

        let started = std::time::Instant::now();
        let rec = recover_with_bin_for_test(&shim, b"descendant cleanup fixture");
        let elapsed = started.elapsed();
        assert!(rec.is_none(), "failed Rizin must not emit partial facts");
        assert!(
            elapsed < Duration::from_secs(2),
            "lingering descendant retained the worker for {elapsed:?}"
        );

        let descendant: i32 = std::fs::read_to_string(&descendant_pid)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        for _ in 0..100 {
            // SAFETY: signal 0 performs existence/permission probing only.
            #[allow(unsafe_code)]
            let exists = unsafe { libc::kill(descendant, 0) } == 0
                || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
            if !exists {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // SAFETY: signal 0 performs existence/permission probing only.
        #[allow(unsafe_code)]
        let exists = unsafe { libc::kill(descendant, 0) } == 0
            || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
        assert!(!exists, "Rizin descendant survived its leader's exit");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(unix)]
    fn timeout_kills_process_group_joins_reader_and_returns_worker() {
        let _lock = rizin_test_lock();

        // Preserve a caller-installed override even if an assertion panics.
        struct TimeoutReset(u64);
        impl Drop for TimeoutReset {
            fn drop(&mut self) {
                RIZIN_TIMEOUT_SECS.store(self.0, Ordering::SeqCst);
            }
        }
        let previous = RIZIN_TIMEOUT_SECS.swap(1, Ordering::SeqCst);
        let _timeout_reset = TimeoutReset(previous);

        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let dir = unique_shim_dir("filefacts-rizin-timeoutshim");
        std::fs::create_dir_all(&dir).unwrap();
        let shim = dir.join("rizin");
        let leader_pid = dir.join("leader.pid");
        let descendant_pid = dir.join("descendant.pid");
        let mut f = std::fs::File::create(&shim).unwrap();
        writeln!(f, "#!/bin/sh").unwrap();
        writeln!(f, "printf '%s\\n' \"$$\" > '{}'", leader_pid.display()).unwrap();
        writeln!(f, "sleep 300 &").unwrap();
        writeln!(f, "descendant=$!").unwrap();
        writeln!(
            f,
            "printf '%s\\n' \"$descendant\" > '{}'",
            descendant_pid.display()
        )
        .unwrap();
        writeln!(f, "wait \"$descendant\"").unwrap();
        let mut perms = std::fs::metadata(&shim).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&shim, perms).unwrap();
        drop(f);

        let started = std::time::Instant::now();
        let rec = recover_with_bin_for_test(&shim, b"timeout cleanup fixture");
        let elapsed = started.elapsed();
        assert!(rec.is_none(), "timed-out Rizin must not emit partial facts");
        assert!(
            elapsed >= Duration::from_millis(900) && elapsed < Duration::from_secs(5),
            "one-second timeout returned after {elapsed:?}"
        );

        let leader: i32 = std::fs::read_to_string(&leader_pid)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let descendant: i32 = std::fs::read_to_string(&descendant_pid)
            .unwrap()
            .trim()
            .parse()
            .unwrap();

        fn process_exists(pid: i32) -> bool {
            // SAFETY: signal 0 performs existence/permission probing only.
            #[allow(unsafe_code)]
            let rc = unsafe { libc::kill(pid, 0) };
            rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
        }

        // The direct child is synchronously waited. Its background child is
        // killed by the same process-group signal and may remain a zombie for a
        // scheduler tick while init adopts it, so give reaping a short grace.
        for _ in 0..100 {
            if !process_exists(leader) && !process_exists(descendant) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!process_exists(leader), "Rizin group leader was not reaped");
        assert!(
            !process_exists(descendant),
            "Rizin descendant survived the process-group timeout"
        );
        assert!(
            !RIZIN_PGIDS
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .contains(&leader),
            "timed-out Rizin remained in the live-process registry"
        );

        let _ = std::fs::remove_dir_all(&dir);
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
