//! Optional rizin/radare2 integration for binary analysis.
//!
//! Stripped binaries — and most malware — produce empty `dynsym` and
//! `symtab` tables, so goblin's parse returns 0 imports/exports/
//! functions. Rizin can recover them through linear disassembly +
//! signature matching + entry-point graph walking.
//!
//! # Discovery model
//!
//! At runtime we look for `rizin` (or `r2`) through the cached external-tool
//! resolver. It checks `PATH` first and then platform fallback locations. If
//! neither is installed, every call here returns `None` and extraction
//! proceeds without rizin's contributions.
//!
//! # Configuration
//!
//! Per file, through [`crate::OpenOptions`]: on/off, the wall-clock budget,
//! a size cap and native-arch slicing travel with each
//! [`crate::ParsedFile`]. What stays process-wide here is what has to: the
//! live process-group registry [`kill_all_rizin_groups`](crate::rizin::kill_all_rizin_groups)
//! reaps from a signal handler, the [`stats`](crate::rizin::stats) counters, the binary discovery, and the latch that
//! turns rizin off for good after too many abandoned output readers.
//!
//! # Subprocess discipline
//!
//! The minimum viable port covers the happy path: spawn, wait for
//! exit with a hard timeout, parse JSON. Hardening for adversarial
//! input (cancellation propagation, output-cap detection, kill-group
//! tracking on truant children) lives in cleave's existing
//! `radare2/mod.rs` and ports across as #75c.

use crate::metric;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
#[cfg(any(target_os = "linux", target_os = "macos"))]
const RIZIN_MEMORY_LIMIT_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Per-process byte cap on a rizin subprocess's stdout. Mirrors
/// cleave's defence: pathological inputs can produce gigabytes of
/// JSON; we kill the process group on overflow and record the reason.
///
/// 200 MiB, doubled from 100 MiB: a 75 MB Go Terraform provider (~84k
/// functions) overflowed 100 MiB in `aflj` alone, and an overflow discards
/// every rizin fact for the binary, so its function names and call edges
/// were invisible to rules.
const MAX_SUBPROCESS_OUTPUT: usize = 200 * 1024 * 1024;
/// How long to wait for the stdout drain thread after the child is known dead
/// before abandoning it. The drain normally returns the instant the last write
/// handle closes; this bound exists only so a handle we cannot reach (one an
/// unrelated process inherited through the Windows `CreateProcess` inheritance
/// race, say) degrades to a single lost recovery instead of parking the Rayon
/// caller — and with it every archive queued behind its memory-gate permit —
/// forever. Generous on purpose: a drain starved by the scheduler under heavy
/// parallel load must never be mistaken for a stuck one.
const DRAIN_GRACE: Duration = Duration::from_secs(60);

/// Full analysis plus the four JSON tables imported by [`RizinRecovery`].
const RIZIN_METRICS_SCRIPT: &str =
    "iij; echo ===SEP===; iEj; echo ===SEP===; aaa; echo ===SEP===; aflj; echo ===SEP===; iSj";

/// [`RIZIN_METRICS_SCRIPT`] with `aa; aac` (symbols, entry points, call
/// targets) in place of `aaa`, for PE images on x86/x86-64 — see
/// [`analysis_script`].
const RIZIN_METRICS_SCRIPT_PE_X86: &str =
    "iij; echo ===SEP===; iEj; echo ===SEP===; aa; aac; echo ===SEP===; aflj; echo ===SEP===; iSj";

/// [`RIZIN_METRICS_SCRIPT`] with `aa; aac; aap` (adds the function-prelude
/// scan) in place of `aaa`, the default for every other input — see
/// [`analysis_script`].
const RIZIN_METRICS_SCRIPT_PRELUDE: &str = "iij; echo ===SEP===; iEj; echo ===SEP===; aa; aac; aap; echo ===SEP===; aflj; echo ===SEP===; iSj";

/// [`RIZIN_METRICS_SCRIPT`] with `aalg; aa; aac` in place of `aaa`, for Go
/// images — see [`analysis_script`]. `aalg` ("recover and analyze all Golang
/// functions and strings") is the pclntab pass that `aaa` reaches only after
/// its full discovery sweep. It runs FIRST: `aalg` names the functions it
/// creates but does not rename ones `aa`/`aac` already created as `fcn.*`,
/// so the old `aa; aac; aalg` order left most of a Go binary unnamed.
const RIZIN_METRICS_SCRIPT_GO: &str = "iij; echo ===SEP===; iEj; echo ===SEP===; aalg; aa; aac; echo ===SEP===; aflj; echo ===SEP===; iSj";

/// Rizin switches that remove work whose output filefacts never consumes.
/// Keep this separate from the input path so the contract is directly tested.
/// The analysis script (`-c …`) is appended per input by [`analysis_script`].
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
];

/// The rizin script for `bytes`, with a label for logs.
///
/// `symbol_count` is the size of the format parser's static symbol
/// inventory (imports, exports, symbol-table functions) for this input.
///
/// * PE images for i386/x86-64 take `aa; aac`: on every such sample
///   measured (four installers/DLLs, 1.8–11 MB, 2026-09-02) it reproduced
///   `aaa`'s function table — names, offsets, sizes, basic blocks,
///   complexity — at 40–55% of the time, differing only in a few percent
///   of call references (`aar`).
/// * An input with no symbol inventory at all keeps `aaa`: with nothing to
///   seed `aa`, discovery depends on the full pass (a stripped, symbol-less
///   x86-64 ELF found 2,849 of 4,812 functions any other way).
/// * Everything else takes `aa; aac; aap` (adds the function-prelude scan):
///   94–100% of `aaa`'s functions at 3–8× less time on the arm64, x86-64
///   ELF and Mach-O samples (overdrive arm64 `.so` 3,646 of 3,741 in 2.8 s
///   vs 25 s; a 61 MB arm64 Mach-O 89,227 of 89,675 in 63 s vs 209 s).
///
/// * Go images take `aalg; aa; aac`: `aalg` is rizin's dedicated pclntab
///   pass, which `aaa` runs only at the end of its full sweep. It must come
///   first. Re-measured 2026-09-24 (rizin 0.8.2) on the local toolchain's
///   `go/pkg/tool/linux_amd64/{vet,fix}`: `aa; aac; aalg` left 4,340 of
///   7,065 and 4,396 of 7,140 functions as unnamed `fcn.*`; `aalg; aa; aac`
///   left 58 and 60, for ~1 s more. On a 75 MB Go Terraform provider it
///   left 1,105 unnamed instead of 22,777 — including the loader functions a
///   rule needed — and ran faster (173 s vs 211 s).
///
/// The non-Go fast scripts are approximations of `aaa`, accepted for the
/// latency; the function count and CFG aggregates they feed can differ by
/// a few percent from a full pass. The Go script is not an approximation:
/// it reproduced the full table exactly on both samples, because it runs the
/// same pclntab recovery `aaa` would.
fn analysis_script(
    bytes: &[u8],
    symbol_count: usize,
    go_function_metadata: bool,
) -> (&'static str, &'static str) {
    if go_function_metadata {
        // Go's pclntab names come from `aalg`, which the PE/prelude scripts
        // do not run — they find the code ranges but leave these functions
        // as fcn.*. Calling it directly costs the recovery without `aaa`'s
        // preceding full sweep.
        (RIZIN_METRICS_SCRIPT_GO, "go-pclntab")
    } else if is_pe_x86(bytes) {
        (RIZIN_METRICS_SCRIPT_PE_X86, "pe-x86")
    } else if symbol_count == 0 {
        (RIZIN_METRICS_SCRIPT, "full")
    } else {
        (RIZIN_METRICS_SCRIPT_PRELUDE, "prelude")
    }
}

/// A PE image whose COFF machine field is i386 (0x14c) or x86-64 (0x8664).
fn is_pe_x86(bytes: &[u8]) -> bool {
    if !bytes.starts_with(b"MZ") {
        return false;
    }
    crate::bytes::u32_le(bytes, 0x3c)
        .and_then(|e_lfanew| bytes.get(e_lfanew as usize..))
        .is_some_and(|nt| {
            nt.starts_with(b"PE\0\0")
                && matches!(crate::bytes::u16_le(nt, 4), Some(0x014c | 0x8664))
        })
}

// ---------------------------------------------------------------------------
// Per-open settings.
// ---------------------------------------------------------------------------

/// The rizin settings of one [`crate::ParsedFile`], set through
/// [`crate::OpenOptions`] and carried to every recovery it runs. Nothing here
/// is process-wide, so two files opened with different settings never see
/// each other's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Settings {
    /// Run rizin at all (when it is installed).
    pub(crate) enabled: bool,
    /// Wall-clock budget for one rizin run.
    pub(crate) timeout: Duration,
    /// Skip rizin for inputs larger than this many bytes. `None` = no cap.
    /// A full `aaa` on a 100 MB+ stripped binary costs minutes; a cap keeps a
    /// directory of giant signed apps from dominating a latency-sensitive
    /// scan.
    pub(crate) max_bytes: Option<usize>,
    /// Slice a fat Mach-O to the host-native architecture before rizin runs,
    /// instead of handing rizin the whole universal binary. Halves the work on
    /// a two-arch binary and skips a slice that never executes on this host.
    pub(crate) native_arch_only: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout: RIZIN_TIMEOUT,
            max_bytes: None,
            native_arch_only: false,
        }
    }
}

impl Settings {
    /// Whether these settings let rizin analyse `bytes` at all: it is enabled
    /// and `bytes` is within the size cap. A refusal here is a property of the
    /// settings, which [`cache_fingerprint`] keys, so the result it leaves
    /// behind is as cacheable as a full recovery. Rizin being installed is
    /// checked separately, by the recovery itself.
    pub(crate) fn admits(&self, bytes: &[u8]) -> bool {
        if !self.enabled {
            return false;
        }
        match self.max_bytes {
            Some(max) if bytes.len() > max => {
                tracing::debug!(
                    bytes = bytes.len(),
                    max,
                    "rizin recover: skipped (over size cap)"
                );
                false
            }
            _ => true,
        }
    }
}

// ---------------------------------------------------------------------------
// Process-wide hardening state.
// ---------------------------------------------------------------------------

/// Live rizin process-group IDs. Populated on spawn, drained in every
/// cleanup path. `kill_all_rizin_groups` reads this list and SIGKILLs
/// every entry so host CLI signal handlers can reap in-flight rizin
/// subprocesses before a forced `process::exit`.
static RIZIN_PGIDS: Mutex<Vec<i32>> = Mutex::new(Vec::new());

/// Drain threads abandoned after [`DRAIN_GRACE`] (see `join_drain`). Non-zero
/// means some process outside our reach held a copy of a rizin stdout pipe.
static RIZIN_DRAINS_ABANDONED: AtomicU64 = AtomicU64::new(0);

/// Latched by `join_drain` once [`RIZIN_MAX_ABANDONED_DRAINS`] readers have
/// been abandoned: rizin then stays off for the rest of the process, whatever
/// a file's [`Settings`] ask for. Process-wide because the leak it stops is:
/// every abandoned reader is a parked thread of this process. Never cleared.
static RIZIN_SELF_DISABLED: AtomicBool = AtomicBool::new(false);

/// Abandoned drains after which rizin disables itself for the rest of the
/// process. Each abandoned reader is an OS thread parked in `read_to_end`
/// forever, holding a pipe fd and up to [`MAX_SUBPROCESS_OUTPUT`] of buffer —
/// there is no portable way to cancel it. One is an anomaly; a steady trickle
/// on a days-old worker is a leak with no bound but uptime, and a host whose
/// rizin children keep escaping containment is not going to start behaving.
const RIZIN_MAX_ABANDONED_DRAINS: u64 = 8;

/// Poll interval while waiting for a rizin child to exit.
///
/// A plain sleep on purpose. This loop used to consult a caller-installed hook
/// so a waiting pool worker could run other jobs instead of parking (scan
/// installed `rayon::yield_now`), which made the wait re-entrant: the hook ran
/// another job to completion on this thread, and a job that blocked never came
/// back. `try_wait` was then never called again — leaving the exited child
/// unreaped — and the timeout below, tested only at the loop head, never fired.
/// A worker suspended mid-wait still holds everything its caller held, which is
/// how a scan deadlocked with a zombie rizin and every worker parked
/// (2026-09-05). Parking one worker for the length of a disassembly is the
/// price of a wait loop that cannot be suspended.
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(100);

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
    #[cfg(unix)]
    {
        let pgids: Vec<i32> = RIZIN_PGIDS.lock().map(|g| g.clone()).unwrap_or_default();
        for pgid in &pgids {
            // SAFETY: libc::kill with a negative pid sends the signal to
            // the process group. Async-signal-safe; tolerates already-dead
            // groups (ESRCH) silently.
            #[allow(unsafe_code)]
            unsafe {
                libc::kill(-(*pgid as libc::pid_t), libc::SIGKILL);
            }
        }
    }
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

/// Stdout reader threads abandoned so far (see `join_drain`). Each one is a
/// permanently parked thread; a long-lived host should surface this on its
/// heartbeat, and rizin turns itself off at `RIZIN_MAX_ABANDONED_DRAINS`.
#[must_use]
pub fn abandoned_drains() -> u64 {
    RIZIN_DRAINS_ABANDONED.load(Ordering::Relaxed)
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
        abandoned_drains = abandoned_drains(),
        timeout_rate_pct = (timeouts as f64 / total_f) * 100.0,
        failure_rate_pct = (failures as f64 / total_f) * 100.0,
        "filefacts rizin subprocess statistics"
    );
}

/// One-shot binary probe. The shared resolver caches the discovered path so we
/// don't search PATH or fallback locations per file.
fn rizin_binary() -> Option<&'static Path> {
    static CACHED: OnceLock<Option<std::path::PathBuf>> = OnceLock::new();
    CACHED
        .get_or_init(|| {
            // Prefer `rizin` (modern); fall back to `radare2` / `r2`.
            for name in ["rizin", "radare2", "r2"] {
                if let Some(path) = crate::tools::resolve(name) {
                    return Some(path);
                }
            }
            None
        })
        .as_deref()
}

/// `true` when rizin (or a compatible drop-in) is available.
/// Cheap — does not spawn anything; only checks the cached probe.
pub fn available() -> bool {
    rizin_binary().is_some()
}

/// rizin's self-reported version string, probed once and cached.
///
/// Used only to invalidate the disk cache across rizin upgrades, so the
/// exact text is opaque — any change that alters analysis output also
/// changes this line. `None` when rizin isn't installed or the probe
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

/// Cache discriminator for the rizin side of an extraction: everything about
/// rizin that changes a *persisted* result.
///
/// Folded into the disk-cache key (see [`crate::cache::cache_key`]) so a
/// payload recovered under one rizin setup is never served to an open with a
/// different one. It captures:
///
/// * whether rizin runs at all — not installed, or turned off by the
///   settings, both give the same no-rizin result and share `rizin=none`;
/// * its version — an upgraded rizin that discovers more functions must not
///   reuse an older run's recovery;
/// * native-arch slicing — a fat Mach-O analysed as a single host slice
///   yields different symbols than the whole universal binary, so the host
///   arch is mixed in while that mode is active;
/// * the size cap — an input over it deterministically gets no recovery.
///
/// The timeout is deliberately *excluded*. A run that completes is the same
/// whatever its budget, and one that times out (like an output-cap kill or
/// the abandoned-drain latch) marks its payload
/// [`crate::cache::Computed::Transient`], which is never written. Keying on
/// it would only split identical entries between hosts with different
/// deadlines.
pub(crate) fn cache_fingerprint(settings: &Settings) -> String {
    if !settings.enabled || !available() {
        return "rizin=none".to_string();
    }
    let version = rizin_version().unwrap_or("unknown");
    // `opaque-v6`: Go recoveries come from `aalg; aa; aac`; PE x86/x86-64 from
    // `aa; aac`, everything else from `aa; aac; aap` with an `aaa` rerun under
    // the coverage floor (see `analysis_script`); cached extractions from an
    // earlier policy must not mix.
    let mut fingerprint = format!("rizin={version}|policy=opaque-v6");
    if settings.native_arch_only {
        fingerprint.push_str("|native=");
        fingerprint.push_str(std::env::consts::ARCH);
    }
    if let Some(max) = settings.max_bytes {
        fingerprint.push_str(&format!("|max_bytes={max}"));
    }
    fingerprint
}

/// Run rizin recovery sized to the caller's static symbol inventory, which picks
/// the analysis depth (see [`analysis_script`]).
///
/// The caller gates on [`Settings::admits`] first: a refusal there is a stable
/// outcome of the settings, while `None` from here means a run that should
/// have happened did not complete (rizin missing, timed out, killed on the
/// output cap, or latched off after too many abandoned drains).
pub(crate) fn recover_with_symbols(
    bytes: &[u8],
    symbol_count: usize,
    go_function_metadata: bool,
    settings: &Settings,
) -> Option<RizinRecovery> {
    if RIZIN_SELF_DISABLED.load(Ordering::Acquire) {
        return None;
    }
    let bin = rizin_binary()?;

    // In-run memo keyed by content hash. Archives routinely carry the same
    // binary several times (a vsix shipping per-language duplicates of every
    // Roslyn DLL, vendored copies of one .so) and each copy previously paid a
    // full `aaa` run — two identical 6.9 MB ELFs were 65 s each on one C#
    // vsix. The recovery is a pure function of the bytes and the script, so
    // replaying the parsed tables is exactly the work the second spawn would
    // redo. This is not the persistent analysis cache (which CLEAVE_SKIP_CACHE
    // governs): it lives and dies with the process. Failures are memoized
    // too — a timeout on these bytes would time out again under the same
    // budget, which is why the budget is part of the key: a file opened with
    // a longer timeout must get its own attempt. Bounded by entry count; on
    // overflow the map resets (duplicates cluster in time, so recency is all
    // we need).
    const RIZIN_MEMO_MAX: usize = 512;
    static MEMO: std::sync::Mutex<
        Option<std::collections::HashMap<[u8; 32], Option<RizinRecovery>>>,
    > = std::sync::Mutex::new(None);
    let key: [u8; 32] = {
        use sha2::Digest as _;
        let mut hasher = sha2::Sha256::new();
        hasher.update(bytes);
        // The Go path selects a different Rizin script, so it must not share
        // an in-process recovery memo entry with the generic PE path.
        hasher.update([go_function_metadata as u8]);
        hasher.update(settings.timeout.as_nanos().to_le_bytes());
        hasher.finalize().into()
    };
    if let Ok(guard) = MEMO.lock()
        && let Some(map) = guard.as_ref()
        && let Some(hit) = map.get(&key)
    {
        tracing::debug!(bytes = bytes.len(), "rizin recover: in-run memo hit");
        return hit.clone();
    }
    let result = recover_with_bin(
        bin,
        bytes,
        symbol_count,
        go_function_metadata,
        settings.timeout,
    );
    if let Ok(mut guard) = MEMO.lock() {
        let map = guard.get_or_insert_with(std::collections::HashMap::default);
        if map.len() >= RIZIN_MEMO_MAX {
            map.clear();
        }
        map.insert(key, result.clone());
    }
    result
}

/// `recover()` with the rizin binary path passed in. Production path
/// uses the cached PATH probe; tests use this entry to inject a fake
/// `rizin` shim so the spawn/drain/parse pipeline can be exercised
/// deterministically without a real rizin install.
#[cfg(test)]
fn recover_with_bin_for_test(bin: &Path, bytes: &[u8]) -> Option<RizinRecovery> {
    recover_with_bin(bin, bytes, 0, false, RIZIN_TIMEOUT)
}

fn recover_with_bin(
    bin: &Path,
    bytes: &[u8],
    symbol_count: usize,
    go_function_metadata: bool,
    timeout: Duration,
) -> Option<RizinRecovery> {
    let (script, label) = analysis_script(bytes, symbol_count, go_function_metadata);
    recover_with_script(bin, bytes, script, label, timeout)
}

fn recover_with_script(
    bin: &Path,
    bytes: &[u8],
    script: &'static str,
    script_label: &'static str,
    timeout: Duration,
) -> Option<RizinRecovery> {
    // The self-disable latch is checked only in `recover_with_symbols`, not
    // here — tests inject a shim via `recover_with_bin_for_test` and need a
    // deterministic spawn path.
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
    cmd.args(RIZIN_METRICS_ARGS)
        .arg("-c")
        .arg(script)
        .arg(&*path_str);
    tracing::debug!(
        bytes = bytes.len(),
        script = script_label,
        "rizin recover: script"
    );
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
    // Contain descendants on Windows the way `process_group(0)` does on Unix.
    // Created immediately after spawn; a helper started in the window before
    // the assignment lands would escape the job, which is what the bounded
    // drain join below exists to survive.
    #[cfg(windows)]
    let job = {
        use std::os::windows::io::AsRawHandle;
        win_job::Job::containing(child.as_raw_handle().cast())
    };
    register_pgid(child_id as i32);
    let _pgid_guard = PgidGuard(child_id as i32);
    let output_cap_hit = Arc::new(AtomicBool::new(false));

    // Drain stdout in a background thread while we wait for exit.
    // Without this, `aflj` output on a binary with thousands of
    // discovered functions overflows the pipe buffer (~64 KB on
    // macOS), the child blocks on write, and `wait_with_output()`
    // deadlocks waiting for exit. Capped at MAX_SUBPROCESS_OUTPUT to
    // bound the worst-case adversarial blob. On
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
    // The buffer comes back over a channel rather than a `JoinHandle` so the
    // wait can be bounded (see `join_drain`); the handle itself is dropped,
    // detaching the thread.
    let (drain_tx, drain_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(1);
    std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        let n = (&mut stdout_handle)
            .take(MAX_SUBPROCESS_OUTPUT as u64)
            .read_to_end(&mut buf)
            .unwrap_or(0);
        if n >= MAX_SUBPROCESS_OUTPUT {
            mark_output_cap_hit(&cap_flag, child_id);
        }
        let _ = drain_tx.send(buf);
    });

    // Poll until the configured duration has elapsed. Comparing elapsed time
    // avoids overflowing `Instant` if a caller supplies an intentionally
    // enormous timeout override. Once the child exits, the reader thread's
    // `read_to_end` returns naturally.
    let mut exit_status = None;
    while started.elapsed() < timeout {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_status = Some(status);
                break;
            }
            Ok(None) => std::thread::sleep(WAIT_POLL_INTERVAL),
            Err(_) => {
                RIZIN_FAILURES.fetch_add(1, Ordering::Relaxed);
                terminate_child(&mut child, child_id);
                #[cfg(windows)]
                if let Some(job) = &job {
                    job.terminate();
                }
                let _ = join_drain(&drain_rx, child_id);
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
            // Killing the whole group (Unix) / job (Windows) closes every
            // inherited copy of stdout. Wait — bounded — before returning so a
            // timed-out analysis does not leave a reader behind holding output
            // its Rayon caller has already been released from.
            #[cfg(windows)]
            if let Some(job) = &job {
                job.terminate();
            }
            let _ = join_drain(&drain_rx, child_id);
            return None;
        }
    };
    // The leader has exited, but a helper process could still hold an inherited
    // stdout descriptor open. Terminate any remaining members of Rizin's private
    // process group before joining, so neither a descendant nor the reader can
    // retain this Rayon caller indefinitely. This is harmless when the group is
    // already empty.
    kill_process_group(child_id);
    // Same on Windows, where `kill_process_group` is a no-op: the job outlives
    // the reaped leader and is addressed by handle, so terminating it here is
    // both safe (no pid to recycle) and necessary (this is the path a shim that
    // backgrounds a helper and exits takes).
    #[cfg(windows)]
    if let Some(job) = &job {
        job.terminate();
    }
    // Wait on every exit-status path—not only success—so a crashing Rizin
    // cannot leave a reader holding a pipe after its caller moves on.
    let stdout_bytes = join_drain(&drain_rx, child_id);
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

/// Apply Unix subprocess hardening: own process group everywhere, plus the
/// platform-specific memory/death limits Linux and macOS support here.
///
/// Any `pre_exec` hook forces Rust's `Command` off its `posix_spawn` path and
/// through `fork()`. In a large multithreaded jemalloc process that means
/// taking every allocator prefork lock. Do not install the hook on FreeBSD,
/// where the previous unconditional RLIMIT_DATA hook produced exactly that
/// contention in live DTrace stacks; `process_group(0)` remains available via
/// `posix_spawn` there.
#[cfg(unix)]
fn apply_unix_hardening(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    cmd.process_group(0);
    // SAFETY: pre_exec runs in the forked child between fork() and
    // exec(). Only async-signal-safe calls are allowed; setrlimit and
    // prctl are both on the POSIX list. No allocation, no locks.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
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
/// Windows analogue of the Unix private process group: a Job Object holding
/// the rizin leader and everything it spawns.
///
/// Unix hardening puts rizin in its own process group so a single `kill(-pgid)`
/// reaps descendants; without an equivalent, a helper that inherited rizin's
/// stdout keeps the pipe's write end open after the leader exits, `read_to_end`
/// never returns, and the Rayon worker blocked on the drain join is retained
/// indefinitely — holding its scan memory-gate permit and stalling every
/// archive queued behind it. `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` also makes
/// the cleanup unconditional: whatever is still in the job dies when the handle
/// closes, including on a panic unwind.
///
/// Addressing the job (not a pid) is what makes this safe to use *after* the
/// leader has been reaped — a pid can be recycled the moment it is waited on,
/// a job handle cannot.
#[cfg(windows)]
#[allow(unsafe_code)] // FFI to kernel32 job-object APIs; each call site documents its invariants.
mod win_job {
    use std::ffi::c_void;

    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x2000;
    /// `JobObjectExtendedLimitInformation`
    const EXTENDED_LIMIT_INFORMATION: i32 = 9;

    #[repr(C)]
    #[derive(Default)]
    struct IoCounters {
        read_ops: u64,
        write_ops: u64,
        other_ops: u64,
        read_bytes: u64,
        write_bytes: u64,
        other_bytes: u64,
    }

    #[repr(C)]
    #[derive(Default)]
    struct BasicLimitInformation {
        per_process_user_time_limit: i64,
        per_job_user_time_limit: i64,
        limit_flags: u32,
        minimum_working_set_size: usize,
        maximum_working_set_size: usize,
        active_process_limit: u32,
        affinity: usize,
        priority_class: u32,
        scheduling_class: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    struct ExtendedLimitInformation {
        basic: BasicLimitInformation,
        io: IoCounters,
        process_memory_limit: usize,
        job_memory_limit: usize,
        peak_process_memory_used: usize,
        peak_job_memory_used: usize,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateJobObjectW(attrs: *mut c_void, name: *const u16) -> *mut c_void;
        fn AssignProcessToJobObject(job: *mut c_void, process: *mut c_void) -> i32;
        fn SetInformationJobObject(
            job: *mut c_void,
            class: i32,
            info: *mut c_void,
            len: u32,
        ) -> i32;
        fn TerminateJobObject(job: *mut c_void, exit_code: u32) -> i32;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }

    /// An owned job handle. Dropping it kills any process still inside.
    pub(super) struct Job(*mut c_void);

    // SAFETY: a job handle is a kernel object usable from any thread; the
    // wrapper only ever passes it back to the Win32 calls above.
    unsafe impl Send for Job {}
    unsafe impl Sync for Job {}

    impl Job {
        /// Create a kill-on-close job and put `process` in it. `None` when any
        /// step fails — the caller then behaves exactly as before this existed
        /// (bounded drain join is the backstop), never worse.
        pub(super) fn containing(process: *mut c_void) -> Option<Self> {
            // SAFETY: null attributes/name request an unnamed default job;
            // the returned handle is checked before use and owned by `Job`.
            let job = unsafe { CreateJobObjectW(std::ptr::null_mut(), std::ptr::null()) };
            if job.is_null() {
                return None;
            }
            let job = Self(job);
            let mut info = ExtendedLimitInformation::default();
            info.basic.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let len = u32::try_from(size_of::<ExtendedLimitInformation>()).unwrap_or(0);
            // SAFETY: `info` is a correctly-shaped, fully-initialised
            // JOBOBJECT_EXTENDED_LIMIT_INFORMATION and `len` is its size.
            let set = unsafe {
                SetInformationJobObject(
                    job.0,
                    EXTENDED_LIMIT_INFORMATION,
                    std::ptr::from_mut(&mut info).cast(),
                    len,
                )
            };
            // SAFETY: both handles are live; failure is reported, not ignored.
            let assigned = unsafe { AssignProcessToJobObject(job.0, process) };
            if set == 0 || assigned == 0 {
                return None;
            }
            Some(job)
        }

        /// Kill every process still in the job. Idempotent and safe to call
        /// after the leader has exited — the job, not a recyclable pid, is
        /// what is addressed.
        pub(super) fn terminate(&self) {
            // SAFETY: `self.0` is a live job handle owned by this value.
            unsafe {
                TerminateJobObject(self.0, 1);
            }
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            // SAFETY: closes the handle exactly once; kill-on-close then
            // reaps anything still inside.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[cfg_attr(not(unix), allow(unused_variables))]
fn kill_process_group(child_id: u32) {
    #[cfg(unix)]
    // SAFETY: libc::kill with negative pid targets the process group.
    // Async-signal-safe; tolerates already-dead groups silently.
    #[allow(unsafe_code)]
    unsafe {
        libc::kill(-(child_id as libc::pid_t), libc::SIGKILL);
    }
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

/// Wait for the stdout drain thread, bounded by [`DRAIN_GRACE`].
///
/// The reader returns as soon as the last copy of the pipe's write end closes.
/// Containment (Unix process group / Windows job) closes the copies we know
/// about; this bound covers the ones we cannot reach — most plausibly a handle
/// another process inherited through the Windows `CreateProcess` handle race —
/// so the worst case is one binary analysed without rizin facts plus a leaked
/// reader thread, never a wedged scan. The thread is deliberately detached
/// rather than joined on expiry: it owns the blocked read, and there is no
/// portable way to cancel it.
fn join_drain(rx: &std::sync::mpsc::Receiver<Vec<u8>>, child_id: u32) -> Vec<u8> {
    match rx.recv_timeout(DRAIN_GRACE) {
        Ok(buf) => buf,
        Err(_) => {
            let abandoned = RIZIN_DRAINS_ABANDONED.fetch_add(1, Ordering::Relaxed) + 1;
            tracing::error!(
                pid = child_id,
                grace_s = DRAIN_GRACE.as_secs(),
                abandoned,
                "rizin stdout still held open after its process tree exited; \
                 abandoning the reader (a process outside our containment \
                 inherited the pipe). Recovery facts for this binary are lost."
            );
            if abandoned == RIZIN_MAX_ABANDONED_DRAINS {
                RIZIN_SELF_DISABLED.store(true, Ordering::Release);
                tracing::error!(
                    abandoned,
                    limit = RIZIN_MAX_ABANDONED_DRAINS,
                    "rizin disabled for the rest of this process: too many \
                     abandoned stdout readers, each a leaked thread and buffer"
                );
            }
            Vec::new()
        }
    }
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
#[derive(Clone)]
pub(crate) struct RizinRecovery {
    imports: Vec<RawImport>,
    exports: Vec<RawExport>,
    functions: Vec<RawFunction>,
    sections: Vec<RawSection>,
}

/// Counts of entries rizin contributed to each typed view through
/// [`RizinRecovery::apply`]. Returned so format extractors can emit
/// the `*.recovered_*_count` metrics that signal "this view was filled in
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

    /// Variant of [`Self::apply`] that also recovers sections. PE / ELF /
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

#[derive(Clone, Deserialize)]
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

#[derive(Clone, Deserialize)]
struct RawExport {
    name: String,
    #[serde(default)]
    vaddr: u64,
}

#[derive(Clone, Deserialize)]
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

#[derive(Clone, Deserialize)]
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
#[derive(Clone, Deserialize)]
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
mod tests;
