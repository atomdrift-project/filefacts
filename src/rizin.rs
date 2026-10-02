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
//! reaps from a signal-handling thread, the [`stats`](crate::rizin::stats)
//! counters, the binary discovery, and the latch that turns rizin off for good
//! after too many abandoned output readers.
//!
//! # Subprocess discipline
//!
//! The minimum viable port covers the happy path: spawn, wait for
//! exit with a hard timeout, parse JSON. Hardening for adversarial
//! input (cancellation propagation, output-cap detection, kill-group
//! tracking on truant children) lives in cleave's existing
//! `radare2/mod.rs` and ports across as #75c.

use crate::metric;
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use serde::Deserialize;

use crate::output::{Metrics, SectionFlag};

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
/// subprocesses before a forced `process::exit`. An entry is removed before
/// its leader is reaped, so the registry never names a group whose id the
/// kernel could already have handed to an unrelated process.
static RIZIN_PGIDS: Mutex<Vec<i32>> = Mutex::new(Vec::new());

/// Temp copies of the inputs live rizin runs are reading. Each is deleted by
/// its run's [`tempfile::TempPath`]; the registry exists for
/// [`kill_all_rizin_groups`], whose caller is about to `process::exit` and so
/// never runs those destructors.
static RIZIN_TEMP_INPUTS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// Drain threads abandoned after [`DRAIN_GRACE`] (see `join_drain`). Non-zero
/// means some process outside our reach held a copy of a rizin stdout pipe.
static RIZIN_DRAINS_ABANDONED: AtomicU64 = AtomicU64::new(0);

/// Latched by `join_drain` once [`RIZIN_MAX_ABANDONED_DRAINS`] readers have
/// been abandoned: rizin then stays off for the rest of the process, whatever
/// a file's [`Settings`] ask for.
///
/// A deliberate process-wide circuit breaker, not configuration: the leak it
/// stops belongs to the process — every abandoned reader is a parked thread
/// of this process, whichever file's settings spawned it — so no per-open
/// setting could bound it. Never cleared.
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

/// Cumulative counters behind [`stats`].
static RIZIN_TOTAL: AtomicU64 = AtomicU64::new(0);
static RIZIN_SUCCESSES: AtomicU64 = AtomicU64::new(0);
static RIZIN_TIMEOUTS: AtomicU64 = AtomicU64::new(0);
static RIZIN_FAILURES: AtomicU64 = AtomicU64::new(0);
static RIZIN_OUTPUT_CAP_EXCEEDED: AtomicU64 = AtomicU64::new(0);

/// Lock a registry, recovering it from a poisoned lock: the registries are
/// plain lists that no panic can leave half-updated, and the reaper must
/// still find every live group after some unrelated thread panicked.
fn registry<T>(lock: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(PoisonError::into_inner)
}

fn register_pgid(pgid: i32) {
    registry(&RIZIN_PGIDS).push(pgid);
}

fn unregister_pgid(pgid: i32) {
    let mut g = registry(&RIZIN_PGIDS);
    if let Some(idx) = g.iter().position(|&p| p == pgid) {
        g.swap_remove(idx);
    }
}

/// SIGKILL the process group of every currently-live rizin subprocess, and
/// delete the temp copies of their inputs.
///
/// For a host's shutdown path before `process::exit`, which skips the
/// destructors that would otherwise do both. Call it from a signal-handling
/// *thread* — the `ctrlc` crate's handler, a `signal-hook` iterator — not
/// from an async signal handler: it takes a lock and allocates.
///
/// Idempotent: entries are removed from the registries by the normal cleanup
/// paths, so calling this after a clean shutdown is a no-op. On non-Unix
/// only the temp files are removed; rizin's job object dies with the
/// process.
pub fn kill_all_rizin_groups() {
    #[cfg(unix)]
    {
        let pgids: Vec<i32> = registry(&RIZIN_PGIDS).clone();
        for pgid in pgids {
            // SAFETY: libc::kill with a negative pid sends the signal to the
            // process group; an already-dead group is ESRCH, ignored. The
            // registry drops a group before its leader is reaped, so the id
            // cannot have been recycled.
            #[allow(unsafe_code)]
            unsafe {
                libc::kill(-(pgid as libc::pid_t), libc::SIGKILL);
            }
        }
    }
    let inputs: Vec<PathBuf> = registry(&RIZIN_TEMP_INPUTS).clone();
    for path in inputs {
        let _ = std::fs::remove_file(path);
    }
}

/// Cumulative rizin subprocess counters for this process; see [`stats`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Stats {
    /// Recovery runs attempted.
    pub total: u64,
    /// Runs that exited cleanly with output.
    pub successes: u64,
    /// Runs killed at their wall-clock budget.
    pub timeouts: u64,
    /// Runs that could not be started, crashed, or produced nothing.
    pub failures: u64,
    /// Runs killed for writing more than the output cap.
    pub output_cap_exceeded: u64,
    /// Stdout readers abandoned; same as [`abandoned_drains`].
    pub abandoned_drains: u64,
}

/// Cumulative rizin subprocess counters for this process.
pub fn stats() -> Stats {
    Stats {
        total: RIZIN_TOTAL.load(Ordering::Relaxed),
        successes: RIZIN_SUCCESSES.load(Ordering::Relaxed),
        timeouts: RIZIN_TIMEOUTS.load(Ordering::Relaxed),
        failures: RIZIN_FAILURES.load(Ordering::Relaxed),
        output_cap_exceeded: RIZIN_OUTPUT_CAP_EXCEEDED.load(Ordering::Relaxed),
        abandoned_drains: abandoned_drains(),
    }
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
    let Stats {
        total,
        successes,
        timeouts,
        failures,
        output_cap_exceeded,
        abandoned_drains,
    } = stats();
    if total == 0 {
        return;
    }
    let total_f = total as f64;
    tracing::info!(
        total_calls = total,
        successes,
        timeouts,
        failures,
        output_cap_exceeded,
        abandoned_drains,
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
///
/// Every thread that needs the fingerprint waits on this probe, so it runs
/// under the same containment as an analysis, with a short deadline and a
/// small output cap: a wedged or chatty binary on `PATH` costs one bounded
/// wait and then reads as "version unknown", never a hung scan.
fn rizin_version() -> Option<&'static str> {
    static VERSION: OnceLock<Option<String>> = OnceLock::new();
    VERSION
        .get_or_init(|| version_of(rizin_binary()?, VERSION_PROBE_TIMEOUT))
        .as_deref()
}

/// Deadline for the `rizin -v` probe. Measured in milliseconds normally.
const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// More than any version banner; the probe keeps its first line.
const VERSION_PROBE_MAX_OUTPUT: usize = 64 * 1024;

/// The first line `bin -v` prints, run hardened and bounded.
fn version_of(bin: &Path, timeout: Duration) -> Option<String> {
    let mut cmd = Command::new(bin);
    cmd.arg("-v");
    let RunOutcome::Exited { status, stdout, .. } =
        run_hardened(cmd, timeout, VERSION_PROBE_MAX_OUTPUT)
    else {
        return None;
    };
    if !status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&stdout);
    let first = text.lines().next().unwrap_or("").trim();
    (!first.is_empty()).then(|| first.to_string())
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
    // governs): it lives and dies with the process.
    //
    // Only outcomes the bytes decide are memoized (see `Attempt`): a
    // recovery, an empty or crashed run, an output-cap kill, and a timeout —
    // the last because these bytes would time out again under the same
    // budget, which is why the budget is part of the key. A run that failed
    // for reasons of its own (no temp space, spawn refused, reader
    // abandoned, killed from outside) is not, so the next copy gets a fresh
    // attempt.
    let key: [u8; 32] = {
        use sha2::Digest as _;
        let mut hasher = sha2::Sha256::new();
        hasher.update(bytes);
        // The Go path selects a different Rizin script, so it must not share
        // an in-process recovery memo entry with the generic PE path.
        hasher.update([u8::from(go_function_metadata)]);
        hasher.update(settings.timeout.as_nanos().to_le_bytes());
        hasher.finalize().into()
    };
    if let Some(hit) = registry(&RIZIN_MEMO).get(&key) {
        tracing::debug!(bytes = bytes.len(), "rizin recover: in-run memo hit");
        return hit.clone();
    }
    let attempt = attempt_with_bin(
        bin,
        bytes,
        symbol_count,
        go_function_metadata,
        settings.timeout,
    );
    if attempt.deterministic {
        registry(&RIZIN_MEMO).insert(key, attempt.recovery.clone(), attempt.weight);
    }
    attempt.recovery
}

/// The in-run recovery memo; see [`recover_with_symbols`].
static RIZIN_MEMO: Mutex<Memo> = Mutex::new(Memo::new());

/// Most entries the memo holds before it resets.
const RIZIN_MEMO_MAX_ENTRIES: usize = 512;

/// Most rizin output, in bytes, the memo's entries may stand for before it
/// resets. A recovery parsed from up to [`MAX_SUBPROCESS_OUTPUT`] of JSON is
/// itself that order of size, so a count bound alone let 512 large entries
/// reach many gigabytes.
const RIZIN_MEMO_MAX_BYTES: usize = 256 * 1024 * 1024;

/// Accounting weight of a memoized failure, which holds no tables.
const RIZIN_MEMO_FAILURE_WEIGHT: usize = 64;

/// Recoveries by content key, bounded by entry count and by the rizin output
/// they were parsed from. On overflow the map resets: duplicates cluster in
/// time, so recency is all it needs.
struct Memo {
    map: Option<std::collections::HashMap<[u8; 32], Option<RizinRecovery>>>,
    bytes: usize,
}

impl Memo {
    const fn new() -> Self {
        Self {
            map: None,
            bytes: 0,
        }
    }

    /// The remembered outcome for `key`: a recovery, or `None` for a run
    /// that recovered nothing.
    fn get(&self, key: &[u8; 32]) -> Option<&Option<RizinRecovery>> {
        self.map.as_ref()?.get(key)
    }

    /// Remember `recovery`, which was parsed from `weight` bytes of output.
    /// One entry too large to share the budget is not remembered at all.
    fn insert(&mut self, key: [u8; 32], recovery: Option<RizinRecovery>, weight: usize) {
        let weight = weight.max(RIZIN_MEMO_FAILURE_WEIGHT);
        if weight > RIZIN_MEMO_MAX_BYTES / 4 {
            return;
        }
        let map = self
            .map
            .get_or_insert_with(std::collections::HashMap::default);
        if map.len() >= RIZIN_MEMO_MAX_ENTRIES || self.bytes + weight > RIZIN_MEMO_MAX_BYTES {
            map.clear();
            self.bytes = 0;
        }
        if map.insert(key, recovery).is_none() {
            self.bytes += weight;
        }
    }
}

/// One recovery attempt, and whether the bytes alone decided its outcome.
struct Attempt {
    recovery: Option<RizinRecovery>,
    /// The same bytes under the same budget would end the same way, so the
    /// outcome may be memoized. False for a run that failed for reasons of
    /// its own: no temp space, spawn refused, reader abandoned, killed from
    /// outside.
    deterministic: bool,
    /// Bytes of rizin output the recovery was parsed from: the memo's
    /// estimate of its size.
    weight: usize,
}

impl Attempt {
    fn decided(recovery: Option<RizinRecovery>, weight: usize) -> Self {
        Self {
            recovery,
            deterministic: true,
            weight,
        }
    }

    fn transient() -> Self {
        Self {
            recovery: None,
            deterministic: false,
            weight: 0,
        }
    }
}

/// `recover()` with the rizin binary path passed in. Production path
/// uses the cached PATH probe; tests use this entry to inject a fake
/// `rizin` shim so the spawn/drain/parse pipeline can be exercised
/// deterministically without a real rizin install.
#[cfg(test)]
fn recover_with_bin_for_test(bin: &Path, bytes: &[u8]) -> Option<RizinRecovery> {
    recover_with_bin(bin, bytes, 0, false, RIZIN_TIMEOUT)
}

#[cfg(test)]
fn recover_with_bin(
    bin: &Path,
    bytes: &[u8],
    symbol_count: usize,
    go_function_metadata: bool,
    timeout: Duration,
) -> Option<RizinRecovery> {
    attempt_with_bin(bin, bytes, symbol_count, go_function_metadata, timeout).recovery
}

fn attempt_with_bin(
    bin: &Path,
    bytes: &[u8],
    symbol_count: usize,
    go_function_metadata: bool,
    timeout: Duration,
) -> Attempt {
    let (script, label) = analysis_script(bytes, symbol_count, go_function_metadata);
    attempt_with_script(bin, bytes, script, label, timeout)
}

/// Prefix of the temp copies rizin reads its input from.
const TEMP_INPUT_PREFIX: &str = "filefacts-rizin-";

/// A temp copy of an input, deleted on drop, and listed in
/// [`RIZIN_TEMP_INPUTS`] while it lives.
struct TempInput(tempfile::TempPath);

impl TempInput {
    /// Copy `bytes` to a fresh temp file. `tempfile` creates it with
    /// `O_EXCL`, mode 0600 and a random name, so another local user can
    /// neither predict, pre-create, read nor replace it.
    fn write(bytes: &[u8]) -> io::Result<Self> {
        let mut file = tempfile::Builder::new()
            .prefix(TEMP_INPUT_PREFIX)
            .suffix(".bin")
            .tempfile()?;
        file.write_all(bytes)?;
        file.flush()?;
        let path = file.into_temp_path();
        registry(&RIZIN_TEMP_INPUTS).push(path.to_path_buf());
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempInput {
    fn drop(&mut self) {
        let mut inputs = registry(&RIZIN_TEMP_INPUTS);
        if let Some(idx) = inputs.iter().position(|p| p.as_path() == self.path()) {
            inputs.swap_remove(idx);
        }
        // The `TempPath` field deletes the file once this returns.
    }
}

fn attempt_with_script(
    bin: &Path,
    bytes: &[u8],
    script: &'static str,
    script_label: &'static str,
    timeout: Duration,
) -> Attempt {
    // The self-disable latch is checked only in `recover_with_symbols`, not
    // here — tests inject a shim via `recover_with_bin_for_test` and need a
    // deterministic spawn path.
    RIZIN_TOTAL.fetch_add(1, Ordering::Relaxed);

    // Materialise the bytes as a temp file. Rizin requires a path —
    // there's no stdin mode for binary analysis.
    let Ok(input) = TempInput::write(bytes) else {
        RIZIN_FAILURES.fetch_add(1, Ordering::Relaxed);
        return Attempt::transient();
    };

    // `-NN` disables plugin auto-loading (faster startup, fewer surprises).
    // `-T` skips Rizin's file hashes and `-z` skips its duplicate string-table
    // scan: filefacts computes both independently before this fallback. Local
    // variable/argument recovery is also excluded because none of the imported
    // `aflj` fields use it; function discovery, names/ranges, CFG complexity,
    // basic blocks, and call edges remain part of the full `aaa` pass. Three-run
    // ELF/Mach-O/PE benchmarks found equality in every field consumed below.
    // `-q` quits after the `-c` script and `scr.color=0` strips ANSI escapes.
    // The `aaa` pass is deliberately fixed for admitted binaries; the
    // surrounding `iij`/`iEj`/`aflj`/`iSj` are table reads. The `===SEP===`
    // sentinels must stay 1:1 with the parser's `split` below. The path goes
    // over as an `OsStr`, so a non-UTF-8 temp dir still names the file.
    let mut cmd = Command::new(bin);
    cmd.args(RIZIN_METRICS_ARGS)
        .arg("-c")
        .arg(script)
        .arg(input.path());
    tracing::debug!(
        bytes = bytes.len(),
        script = script_label,
        "rizin recover: script"
    );

    // Per-run timing so binary-heavy archives can be diagnosed at the
    // file granularity (the cumulative `log_stats` line hides which input
    // ate the time). `bytes.len()` identifies the run alongside the
    // caller's own per-member `rizin_mode=enabled` log.
    let started = std::time::Instant::now();
    tracing::debug!(bytes = bytes.len(), "rizin recover: begin");

    let (status, stdout_bytes, cap_hit) = match run_hardened(cmd, timeout, MAX_SUBPROCESS_OUTPUT) {
        RunOutcome::Exited {
            status,
            stdout,
            cap_hit,
        } => (status, stdout, cap_hit),
        RunOutcome::TimedOut => {
            RIZIN_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                bytes = bytes.len(),
                elapsed_ms = started.elapsed().as_millis(),
                "rizin recover: end (timed out)"
            );
            return Attempt::decided(None, 0);
        }
        RunOutcome::Failed => {
            RIZIN_FAILURES.fetch_add(1, Ordering::Relaxed);
            return Attempt::transient();
        }
    };
    drop(input);
    if cap_hit {
        RIZIN_OUTPUT_CAP_EXCEEDED.fetch_add(1, Ordering::Relaxed);
    }
    // Rizin crashed / aborted — partial stdout is unreliable on a
    // failed run, so we drop it rather than emit phantom data.
    if !status.success() {
        RIZIN_FAILURES.fetch_add(1, Ordering::Relaxed);
        // A SIGKILL we did not send for the output cap came from outside —
        // the reaper, the OOM killer — and says nothing about these bytes.
        if killed_from_outside(status, cap_hit) {
            return Attempt::transient();
        }
        return Attempt::decided(None, 0);
    }
    if stdout_bytes.is_empty() {
        RIZIN_FAILURES.fetch_add(1, Ordering::Relaxed);
        return Attempt::decided(None, 0);
    }
    RIZIN_SUCCESSES.fetch_add(1, Ordering::Relaxed);
    tracing::debug!(
        bytes = bytes.len(),
        elapsed_ms = started.elapsed().as_millis(),
        stdout_bytes = stdout_bytes.len(),
        "rizin recover: end (ok)"
    );
    let weight = stdout_bytes.len();
    let stdout = String::from_utf8_lossy(&stdout_bytes);
    Attempt::decided(Some(parse_recovery_output(&stdout)), weight)
}

/// Whether `status` is a SIGKILL that the output cap does not explain.
#[cfg(unix)]
fn killed_from_outside(status: ExitStatus, cap_hit: bool) -> bool {
    use std::os::unix::process::ExitStatusExt;
    !cap_hit && status.signal() == Some(libc::SIGKILL)
}

#[cfg(not(unix))]
fn killed_from_outside(_: ExitStatus, _: bool) -> bool {
    false
}

/// How a [`run_hardened`] child ended.
enum RunOutcome {
    /// It exited — on its own, or killed for exceeding the output cap — and
    /// its stdout was read to the end (up to the cap).
    Exited {
        status: ExitStatus,
        stdout: Vec<u8>,
        /// Stdout passed the cap, so the process group was killed and
        /// `stdout` is truncated.
        cap_hit: bool,
    },
    /// Still running at the deadline: its process group was killed.
    TimedOut,
    /// The run could not be carried out or supervised — spawn refused, no
    /// pipe, no reader thread, a wait error, or a reader that had to be
    /// abandoned. Says nothing about the input.
    Failed,
}

/// Run `cmd` contained — its own process group with memory and death limits
/// on Unix, a kill-on-close job on Windows — reading at most `cap` bytes of
/// stdout and waiting at most `timeout`. stdin and stderr are null.
///
/// Whatever happens, including a panic unwinding through here, the child's
/// process group is killed and its leader reaped before this returns (see
/// [`ChildGuard`]).
fn run_hardened(mut cmd: Command, timeout: Duration, cap: usize) -> RunOutcome {
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::null());
    apply_unix_hardening(&mut cmd);

    let started = std::time::Instant::now();
    let Ok(child) = cmd.spawn() else {
        return RunOutcome::Failed;
    };
    let mut guard = ChildGuard::new(child);
    let pid = guard.pid;

    // Drain stdout in a background thread while we wait for exit.
    // Without this, `aflj` output on a binary with thousands of
    // discovered functions overflows the pipe buffer (~64 KB on
    // macOS), the child blocks on write, and the wait deadlocks.
    let Some(mut stdout) = guard.child.stdout.take() else {
        return RunOutcome::Failed;
    };
    let output_cap_hit = Arc::new(AtomicBool::new(false));
    let cap_flag = Arc::clone(&output_cap_hit);
    // The reader keeps at most `cap` bytes, then flags the overflow and keeps
    // reading into the void: the child must never block on a full pipe, and
    // the kill that ends it is sent from the supervising loop below, which
    // holds the unreaped leader and so knows the group id is still its own.
    // The buffer comes back over a channel rather than a `JoinHandle` so the
    // wait for it can be bounded (see `join_drain`); the handle itself is
    // dropped, detaching the thread.
    let (drain_tx, drain_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(1);
    let spawned = std::thread::Builder::new()
        .name("filefacts-rizin-drain".into())
        .spawn(move || {
            let mut buf = Vec::new();
            let n = (&mut stdout)
                .take(cap as u64)
                .read_to_end(&mut buf)
                .unwrap_or(0);
            if n >= cap {
                cap_flag.store(true, Ordering::Release);
                let _ = io::copy(&mut stdout, &mut io::sink());
            }
            let _ = drain_tx.send(buf);
        });
    if spawned.is_err() {
        // The closure, and with it the read end, is gone; the guard kills
        // and reaps the child.
        return RunOutcome::Failed;
    }

    // Poll until the configured duration has elapsed. Comparing elapsed time
    // avoids overflowing `Instant` if a caller supplies an intentionally
    // enormous timeout override.
    let mut cap_reported = false;
    loop {
        if !cap_reported && output_cap_hit.load(Ordering::Acquire) {
            cap_reported = true;
            tracing::warn!(
                pid,
                cap_bytes = cap,
                "rizin output cap exceeded; killing process group"
            );
            guard.kill_group();
        }
        match guard.has_exited() {
            Ok(true) => break,
            Ok(false) if started.elapsed() >= timeout => {
                // Killing the whole group (Unix) / job (Windows) closes every
                // inherited copy of stdout. Wait — bounded — before returning
                // so a timed-out analysis does not leave a reader behind
                // holding output its caller has already been released from.
                guard.finish();
                let _ = join_drain(&drain_rx, pid);
                return RunOutcome::TimedOut;
            }
            Ok(false) => std::thread::sleep(WAIT_POLL_INTERVAL),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => {
                guard.finish();
                let _ = join_drain(&drain_rx, pid);
                return RunOutcome::Failed;
            }
        }
    }
    // The leader has exited, but a helper process could still hold an
    // inherited stdout descriptor open. Kill what remains of the group — and,
    // on Windows, the job — before joining, so neither a descendant nor the
    // reader can retain this caller indefinitely. Where `has_exited` leaves
    // the leader unreaped, its zombie still pins the group id, so the kill
    // cannot reach a recycled group.
    let Some(status) = guard.finish() else {
        let _ = join_drain(&drain_rx, pid);
        return RunOutcome::Failed;
    };
    // Wait on every exit-status path—not only success—so a crashing child
    // cannot leave a reader holding a pipe after its caller moves on.
    let Some(stdout) = join_drain(&drain_rx, pid) else {
        return RunOutcome::Failed;
    };
    RunOutcome::Exited {
        status,
        stdout,
        cap_hit: output_cap_hit.load(Ordering::Acquire),
    }
}

/// Owns a contained child from spawn to reap. Registered in [`RIZIN_PGIDS`]
/// while its group may be live; dropping it unreaped — an early return, a
/// panic unwinding through [`run_hardened`] — kills the group and reaps the
/// leader, so no path leaves rizin running unsupervised or as a zombie.
struct ChildGuard {
    child: Child,
    pid: u32,
    /// The leader's exit status, once reaped.
    status: Option<ExitStatus>,
    /// [`Self::finish`] has run: the group is dead and out of the registry.
    finished: bool,
    /// Contains descendants on Windows the way `process_group(0)` does on
    /// Unix. Created immediately after spawn; a helper started in the window
    /// before the assignment lands would escape the job, which is what the
    /// bounded drain join exists to survive.
    #[cfg(windows)]
    job: Option<win_job::Job>,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        let pid = child.id();
        #[cfg(windows)]
        let job = {
            use std::os::windows::io::AsRawHandle;
            win_job::Job::containing(child.as_raw_handle().cast())
        };
        register_pgid(pid.cast_signed());
        Self {
            child,
            pid,
            status: None,
            finished: false,
            #[cfg(windows)]
            job,
        }
    }

    /// Whether the leader has exited. Where the platform has
    /// `waitid(WNOWAIT)` the leader is left unreaped, so its pid — the group
    /// id — stays reserved until [`Self::finish`] reaps it.
    fn has_exited(&mut self) -> io::Result<bool> {
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_vendor = "apple",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "netbsd",
            target_os = "openbsd"
        ))]
        {
            exited_unreaped(self.pid)
        }
        // Elsewhere `try_wait` reaps, leaving a narrow window in which the
        // group kill in `finish` could reach a recycled id.
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_vendor = "apple",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "netbsd",
            target_os = "openbsd"
        )))]
        {
            let status = self.child.try_wait()?;
            if status.is_some() {
                self.status = status;
            }
            Ok(status.is_some())
        }
    }

    /// SIGKILL the leader's process group (Unix) or terminate its job
    /// (Windows), without reaping.
    fn kill_group(&self) {
        kill_process_group(self.pid);
        #[cfg(windows)]
        if let Some(job) = &self.job {
            job.terminate();
        }
    }

    /// Kill what is left of the group, drop it from the registry, then reap
    /// the leader. Idempotent; `None` only when the wait itself fails.
    fn finish(&mut self) -> Option<ExitStatus> {
        if self.finished {
            return self.status;
        }
        self.finished = true;
        self.kill_group();
        // Out of the registry before the reap: once reaped, the id is free
        // for the kernel to reuse and the reaper must no longer signal it.
        unregister_pgid(self.pid.cast_signed());
        // Fallback for platforms without process groups, and for the narrow
        // race where group creation failed before `exec`. A no-op on a child
        // `std` has already reaped.
        let _ = self.child.kill();
        let status = self.child.wait().ok();
        self.status = self.status.or(status);
        self.status
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.finish();
    }
}

/// Whether child `pid` has exited, leaving it unreaped (`WNOWAIT`).
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd"
))]
#[allow(unsafe_code)]
fn exited_unreaped(pid: u32) -> io::Result<bool> {
    // SAFETY: `siginfo_t` is plain old data, valid all-zero. With `WNOHANG`
    // and no state change the kernel leaves `si_pid` as the zero we wrote
    // (Linux documents relying on that); otherwise it fills the struct.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is a valid, writable `siginfo_t`; `pid` is our own
    // unreaped child, so the call cannot touch another process's state.
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &raw mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: after a successful `waitid` the `si_pid` member is initialised
    // (to the child's pid, or still zero when it has not exited).
    Ok(unsafe { info.si_pid() } != 0)
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
    // Read before the fork: the child compares it with `getppid()`.
    #[cfg(target_os = "linux")]
    let parent = std::process::id() as libc::pid_t;
    // SAFETY: the hook runs in the forked child between `fork()` and
    // `exec()`, where only async-signal-safe work is sound — no allocation,
    // no locks. `getppid` and `_exit` are on POSIX's async-signal-safe list.
    // `setrlimit` and `prctl` are not listed, but glibc, musl and libSystem
    // implement both as bare system calls that neither allocate nor lock.
    // `io::Error::last_os_error` wraps the raw errno without allocating.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[allow(unsafe_code)]
    unsafe {
        cmd.pre_exec(move || {
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
                libc::setrlimit(libc::RLIMIT_AS, &raw const limit);
                // Ask the kernel to SIGKILL this subprocess if the parent
                // dies without running our own cleanup — covers
                // panic/abort/SIGKILL/OOM paths where no signal handler gets
                // to run `kill_all_rizin_groups`. "Parent" is the forking
                // *thread*; it blocks supervising this child until it is
                // reaped, so it cannot exit first. Refuse to run unguarded
                // if the kernel will not arm it.
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong) != 0 {
                    return Err(io::Error::last_os_error());
                }
                // A parent that died between `fork` and the `prctl` above
                // never delivers the signal; the child has already been
                // reparented, which `getppid` shows. Exit rather than run
                // orphaned.
                if libc::getppid() != parent {
                    libc::_exit(1);
                }
            }
            libc::setrlimit(libc::RLIMIT_DATA, &raw const limit);
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn apply_unix_hardening(_: &mut Command) {}

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

/// SIGKILL the process group led by `child_id`. Only [`ChildGuard`] calls
/// this, while the leader is still unreaped, so the id is still its own.
/// No-op on non-Unix.
#[cfg_attr(not(unix), allow(unused_variables))]
fn kill_process_group(child_id: u32) {
    #[cfg(unix)]
    // SAFETY: libc::kill with negative pid targets the process group.
    // Tolerates already-dead groups (ESRCH) silently.
    #[allow(unsafe_code)]
    unsafe {
        libc::kill(-(child_id as libc::pid_t), libc::SIGKILL);
    }
}

/// Wait for the stdout drain thread, bounded by [`DRAIN_GRACE`]. `None` when
/// the reader had to be abandoned.
///
/// The reader returns as soon as the last copy of the pipe's write end closes.
/// Containment (Unix process group / Windows job) closes the copies we know
/// about; this bound covers the ones we cannot reach — most plausibly a handle
/// another process inherited through the Windows `CreateProcess` handle race —
/// so the worst case is one binary analysed without rizin facts plus a leaked
/// reader thread, never a wedged scan. The thread is deliberately detached
/// rather than joined on expiry: it owns the blocked read, and there is no
/// portable way to cancel it.
fn join_drain(rx: &std::sync::mpsc::Receiver<Vec<u8>>, child_id: u32) -> Option<Vec<u8>> {
    match rx.recv_timeout(DRAIN_GRACE) {
        Ok(buf) => Some(buf),
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
            None
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
