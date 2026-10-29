//! Optional rizin integration for binary analysis.
//!
//! Stripped binaries — and most malware — have empty `dynsym` and `symtab`
//! tables, so the format parsers find no imports, exports or functions.
//! Rizin recovers them through linear disassembly, signature matching and
//! entry-point graph walking.
//!
//! # Discovery
//!
//! `rizin` is looked up once per process through the cached external-tool
//! resolver, which checks `PATH` and then platform fallback locations. When
//! it is not installed every recovery returns `None` and extraction proceeds
//! without rizin's contributions.
//!
//! # Configuration
//!
//! Per file, through [`crate::OpenOptions`]: on/off, the wall-clock budget, a
//! size cap and native-arch slicing travel with each [`crate::ParsedFile`].
//! The host sets the one process-wide knob, the number of runs allowed at
//! once ([`set_max_concurrent_runs`](crate::rizin::set_max_concurrent_runs)); the library reads no environment.
//! The rest of the process-wide state is process-wide by nature: the
//! registry of live process groups [`kill_all_rizin_groups`](crate::rizin::kill_all_rizin_groups) reaps from a
//! signal-handling thread, the [`stats`](crate::rizin::stats) counters, the in-run memo, and the
//! latch that turns rizin off after too many abandoned output readers.
//!
//! # Subprocess containment
//!
//! Rizin parses hostile bytes, so every run is contained: its own process
//! group (on Windows, a kill-on-close job object), a 4 GiB memory limit that
//! never loosens a tighter inherited one (Linux `RLIMIT_AS`/`RLIMIT_DATA`,
//! the Windows job's process-memory limit), death with its parent (Linux
//! `PR_SET_PDEATHSIG`, a watchdog on macOS), an allowlisted environment, null
//! stdin and stderr, stdout capped and drained on its own thread, and a
//! wall-clock deadline after which the whole group is killed. Whatever path a
//! run leaves by, a panic included, its group is killed and its leader reaped
//! before the call returns. macOS has no enforceable per-process memory
//! limit: XNU rejects an `RLIMIT_DATA` below the address space a forked child
//! already maps, so a 4 GiB cap fails there with `EINVAL`.

mod process;
mod recovery;

use std::io::{self, Write as _};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use process::{RunOutcome, killed_from_outside, rizin_command};
pub(crate) use recovery::RizinRecovery;
use recovery::parse_recovery_output;

/// Default hard cap on a single Rizin run. `aaa` analysis on a heavily
/// stripped ~14 MB Linux binary needed ~85 s in real measurement, while large
/// but legitimate native images can take several minutes. Ten minutes gives
/// those a useful completion window without letting a pathological subprocess
/// occupy an analysis worker indefinitely.
pub const DEFAULT_RIZIN_TIMEOUT_SECS: u64 = 600;
const RIZIN_TIMEOUT: Duration = Duration::from_secs(DEFAULT_RIZIN_TIMEOUT_SECS);

/// Per-run byte cap on a rizin subprocess's stdout. Pathological inputs can
/// produce gigabytes of JSON; on overflow the process group is killed and
/// the run recorded as capped. Large Go images need more than 100 MiB for
/// `aflj` alone (a 75 MB provider with ~84k functions), and an overflow
/// discards every rizin fact for the binary.
const MAX_SUBPROCESS_OUTPUT: usize = 200 * 1024 * 1024;

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
/// its full discovery sweep. It runs first: `aalg` names the functions it
/// creates but does not rename ones `aa`/`aac` already created as `fcn.*`.
const RIZIN_METRICS_SCRIPT_GO: &str = "iij; echo ===SEP===; iEj; echo ===SEP===; aalg; aa; aac; echo ===SEP===; aflj; echo ===SEP===; iSj";

/// Rizin switches that remove work whose output filefacts never consumes.
/// Kept apart from the input path so the contract is directly tested. The
/// analysis script (`-c …`) and the input path are appended per run.
///
/// `-NN` skips the rc files and plugin auto-loading, `-q` quits after the
/// script, `-T` skips rizin's file hashes and `-z` its string-table scan
/// (filefacts computes both itself), and `scr.color=0` strips ANSI escapes.
/// Local variable/argument recovery is off because no imported `aflj` field
/// uses it; function discovery, names, ranges, CFG complexity, basic blocks
/// and call edges are unaffected.
const RIZIN_METRICS_ARGS: &[&str] = &[
    "-NN",
    "-q",
    "-T",
    "-z",
    "-e",
    "scr.color=0",
    "-e",
    // Rizin's level 0 is DEBUG, not silence. Keep warnings and errors without
    // formatting a recovered-symbol message for every function in large Go images.
    "log.level=3",
    "-e",
    "analysis.vars=false",
];

/// One rizin analysis script, and a label for logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Script {
    /// The `-c` argument. Its `===SEP===` sentinels are 1:1 with the blocks
    /// [`parse_recovery_output`] reads.
    commands: &'static str,
    label: &'static str,
}

/// The rizin script for `bytes`.
///
/// `symbol_count` is the size of the format parser's static symbol
/// inventory (imports, exports, symbol-table functions) for this input.
///
/// * Go images take `aalg; aa; aac`: `aalg` is rizin's dedicated pclntab
///   pass, which `aaa` runs only at the end of its full sweep, and it must
///   come first. With `aa; aac; aalg` most functions of a Go toolchain
///   binary stayed unnamed `fcn.*` (4,340 of 7,065); with `aalg; aa; aac`,
///   58 did, for about a second more.
/// * PE images for i386/x86-64 take `aa; aac`: on the installers and DLLs
///   measured (1.8–11 MB) it reproduced `aaa`'s function table — names,
///   offsets, sizes, basic blocks, complexity — at 40–55% of the time,
///   differing only in a few percent of call references (`aar`).
/// * An input with no symbol inventory at all keeps `aaa`: with nothing to
///   seed `aa`, discovery depends on the full pass (a stripped, symbol-less
///   x86-64 ELF found 2,849 of 4,812 functions any other way).
/// * Everything else takes `aa; aac; aap` (adds the function-prelude scan):
///   94–100% of `aaa`'s functions at 3–8× less time on arm64 and x86-64 ELF
///   and Mach-O images.
///
/// The non-Go fast scripts approximate `aaa`, accepted for the latency; the
/// function count and CFG aggregates they feed can differ by a few percent
/// from a full pass. The Go script is not an approximation: it runs the same
/// pclntab recovery `aaa` would.
fn analysis_script(bytes: &[u8], symbol_count: usize, go_function_metadata: bool) -> Script {
    let (commands, label) = if go_function_metadata {
        (RIZIN_METRICS_SCRIPT_GO, "go-pclntab")
    } else if is_pe_x86(bytes) {
        (RIZIN_METRICS_SCRIPT_PE_X86, "pe-x86")
    } else if symbol_count == 0 {
        (RIZIN_METRICS_SCRIPT, "full")
    } else {
        (RIZIN_METRICS_SCRIPT_PRELUDE, "prelude")
    };
    Script { commands, label }
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
    /// Optional larger deadline for one retry of a timed-out file.
    pub(crate) retry_timeout: Option<Duration>,
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
            retry_timeout: None,
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
// Process-wide supervision state.
// ---------------------------------------------------------------------------

/// Everything rizin runs share: the live-process registries, the shutdown
/// latch, the concurrency gate, the in-run memo and the counters.
///
/// The process has exactly one, [`SUPERVISOR`], which every public function
/// here addresses. Tests build their own, so a test that shuts one down or
/// reaps its groups cannot touch another test's runs.
struct Supervisor {
    /// Live rizin process-group ids. An entry is added on spawn and removed
    /// before its leader is reaped, so the registry never names a group whose
    /// id the kernel could already have handed to an unrelated process.
    pgids: Mutex<Vec<i32>>,
    /// Set by [`Self::kill_all`] and never cleared. Held across launch and
    /// registration, so once it is set no new child starts, including work
    /// already queued behind the gate.
    shutdown: Mutex<bool>,
    /// Temp copies of the inputs live runs are reading. Each is deleted by its
    /// run's [`TempInput`]; the list exists for [`Self::kill_all`], whose
    /// caller is about to `process::exit` and so never runs those destructors.
    temp_inputs: Mutex<Vec<PathBuf>>,
    gate: Gate,
    memo: Mutex<Memo>,
    total: AtomicU64,
    successes: AtomicU64,
    timeouts: AtomicU64,
    failures: AtomicU64,
    output_cap_exceeded: AtomicU64,
    /// Stdout readers abandoned after `process::DRAIN_GRACE`. Non-zero means
    /// a process outside our containment held a copy of a rizin stdout pipe.
    drains_abandoned: AtomicU64,
    /// Latched once [`MAX_ABANDONED_DRAINS`] readers have been abandoned:
    /// rizin then stays off for the rest of the process, whatever a file's
    /// [`Settings`] ask for. A circuit breaker, not configuration: every
    /// abandoned reader is a parked thread of this process, whichever file
    /// spawned it, so no per-open setting could bound the leak. Never
    /// cleared.
    disabled: AtomicBool,
}

/// The process's rizin supervisor.
static SUPERVISOR: Supervisor = Supervisor::new();

/// Abandoned drains after which rizin disables itself for the rest of the
/// process. Each abandoned reader is an OS thread parked in `read_to_end`
/// forever, holding a pipe fd and up to [`MAX_SUBPROCESS_OUTPUT`] of buffer —
/// there is no portable way to cancel it. One is an anomaly; a steady trickle
/// on a days-old worker is a leak with no bound but uptime, and a host whose
/// rizin children keep escaping containment is not going to start behaving.
const MAX_ABANDONED_DRAINS: u64 = 8;

/// Lock `lock`, recovering it from poisoning: every value behind these locks
/// is a plain list, flag or counter that no panic can leave half-updated, and
/// the reaper must still find every live group after an unrelated thread
/// panicked.
fn lock<T>(lock: &Mutex<T>) -> MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Supervisor {
    const fn new() -> Self {
        Self {
            pgids: Mutex::new(Vec::new()),
            shutdown: Mutex::new(false),
            temp_inputs: Mutex::new(Vec::new()),
            gate: Gate::new(),
            memo: Mutex::new(Memo::new()),
            total: AtomicU64::new(0),
            successes: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            output_cap_exceeded: AtomicU64::new(0),
            drains_abandoned: AtomicU64::new(0),
            disabled: AtomicBool::new(false),
        }
    }

    /// See [`kill_all_rizin_groups`].
    fn kill_all(&self) {
        let mut shutdown = lock(&self.shutdown);
        *shutdown = true;
        #[cfg(unix)]
        {
            // Keep the registry locked through signalling. A worker cannot
            // unregister and reap a leader while its group is being addressed.
            let pgids = lock(&self.pgids);
            tracing::debug!(groups = pgids.len(), "rizin shutdown: killing live groups");
            for &pgid in pgids.iter() {
                process::kill_process_group(pgid.cast_unsigned());
            }
        }
        for path in lock(&self.temp_inputs).iter() {
            if let Err(error) = std::fs::remove_file(path) {
                tracing::debug!(path = %path.display(), %error, "rizin shutdown: temp input not removed");
            }
        }
    }

    fn stats(&self) -> Stats {
        Stats {
            total: self.total.load(Ordering::Relaxed),
            successes: self.successes.load(Ordering::Relaxed),
            timeouts: self.timeouts.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            output_cap_exceeded: self.output_cap_exceeded.load(Ordering::Relaxed),
            abandoned_drains: self.drains_abandoned.load(Ordering::Relaxed),
        }
    }

    /// Recover `bytes` with `script` through the rizin at `bin`, answering
    /// from the in-run memo when these bytes were already analysed the same
    /// way.
    ///
    /// Archives routinely carry the same binary several times (per-language
    /// duplicates of every DLL in an extension, vendored copies of one
    /// `.so`), and a recovery is a pure function of the bytes, the script and
    /// the budget, so replaying the parsed tables is exactly the work a
    /// second spawn would redo. The memo lives and dies with the process; it
    /// is not the persistent extraction cache.
    ///
    /// Only outcomes the bytes decide are memoized (see [`Attempt`]): a
    /// recovery, an empty or crashed run, an output-cap kill, and a timeout —
    /// the last because these bytes would time out again under the same
    /// budget, which is why the budget is part of the key. A run that failed
    /// for reasons of its own (no temp space, spawn refused, reader
    /// abandoned, killed from outside) is not, so the next copy gets a fresh
    /// attempt.
    fn recover(
        &self,
        bin: &Path,
        bytes: &[u8],
        script: Script,
        settings: &Settings,
    ) -> Option<RizinRecovery> {
        if self.disabled.load(Ordering::Acquire) {
            tracing::debug!(
                bytes = bytes.len(),
                "rizin recover: skipped (disabled after abandoned readers)"
            );
            return None;
        }
        let key = memo_key(bytes, script, settings);
        if let Some(hit) = lock(&self.memo).get(&key) {
            tracing::debug!(
                bytes = bytes.len(),
                script = script.label,
                "rizin recover: in-run memo hit"
            );
            return hit.clone();
        }
        let attempt = attempt_with_retry(settings.timeout, settings.retry_timeout, |timeout| {
            self.attempt(bin, bytes, script, timeout)
        });
        if attempt.deterministic {
            lock(&self.memo).insert(key, attempt.recovery.clone(), attempt.weight);
        }
        attempt.recovery
    }

    /// One rizin run over `bytes`, counted in [`Self::stats`].
    fn attempt(&self, bin: &Path, bytes: &[u8], script: Script, timeout: Duration) -> Attempt {
        self.total.fetch_add(1, Ordering::Relaxed);

        // Rizin needs a path; it has no stdin mode for binary analysis.
        let input = match TempInput::write(self, bytes) {
            Ok(input) => input,
            Err(error) => {
                self.failures.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(bytes = bytes.len(), %error, "rizin recover: cannot stage the input");
                return Attempt::transient();
            }
        };

        // The path goes over as an `OsStr`, so a non-UTF-8 temp dir still
        // names the file.
        let (mut cmd, setup) = rizin_command(bin);
        cmd.args(RIZIN_METRICS_ARGS)
            .arg("-c")
            .arg(script.commands)
            .arg(input.path());
        let started = Instant::now();
        tracing::debug!(
            bytes = bytes.len(),
            script = script.label,
            timeout_ms = timeout.as_millis(),
            "rizin recover: begin"
        );

        let (status, stdout, cap_hit) = match self.run(cmd, timeout, MAX_SUBPROCESS_OUTPUT, setup) {
            RunOutcome::Exited {
                status,
                stdout,
                cap_hit,
            } => (status, stdout, cap_hit),
            RunOutcome::TimedOut => {
                self.timeouts.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    bytes = bytes.len(),
                    script = script.label,
                    elapsed_ms = started.elapsed().as_millis(),
                    "rizin recover: end (timed out)"
                );
                return Attempt::timed_out();
            }
            // `run` logged why.
            RunOutcome::Failed => {
                self.failures.fetch_add(1, Ordering::Relaxed);
                return Attempt::transient();
            }
        };
        drop(input);
        let elapsed_ms = started.elapsed().as_millis();
        if cap_hit {
            self.output_cap_exceeded.fetch_add(1, Ordering::Relaxed);
        }
        // Partial stdout from a crashed or killed run is unreliable, so it
        // is dropped rather than emitted as phantom data.
        if !status.success() {
            self.failures.fetch_add(1, Ordering::Relaxed);
            // A SIGKILL we did not send for the output cap came from outside —
            // the reaper, the OOM killer — and says nothing about these bytes.
            if killed_from_outside(status, cap_hit) {
                tracing::warn!(
                    bytes = bytes.len(),
                    elapsed_ms,
                    "rizin recover: end (killed from outside)"
                );
                return Attempt::transient();
            }
            tracing::debug!(
                bytes = bytes.len(),
                elapsed_ms,
                %status,
                cap_hit,
                "rizin recover: end (failed)"
            );
            return Attempt::decided(None, 0);
        }
        if stdout.is_empty() {
            self.failures.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                bytes = bytes.len(),
                elapsed_ms,
                "rizin recover: end (no output)"
            );
            return Attempt::decided(None, 0);
        }
        let weight = stdout.len();
        let (recovery, complete) = parse_recovery_output(&String::from_utf8_lossy(&stdout));
        if complete {
            self.successes.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                bytes = bytes.len(),
                elapsed_ms,
                stdout_bytes = weight,
                "rizin recover: end (ok)"
            );
        } else {
            // What parsed is still kept: partial tables beat none on
            // adversarial input. `parse_recovery_output` logged the table.
            self.failures.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                bytes = bytes.len(),
                elapsed_ms,
                stdout_bytes = weight,
                "rizin recover: end (malformed output, partial recovery)"
            );
        }
        Attempt::decided(Some(recovery), weight)
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
/// Terminal operation: future launches are refused. Idempotent: entries are
/// removed from the registries by the normal cleanup paths, so calling this
/// after a clean shutdown is a no-op. On non-Unix only the temp files are
/// removed; rizin's job object dies with the process.
pub fn kill_all_rizin_groups() {
    SUPERVISOR.kill_all();
}

/// Allow at most `limit` rizin runs at once in this process; `None` lifts the
/// limit, which is the default.
///
/// Rizin is the memory-heavy step of an extraction, so a host that analyses
/// many files in parallel can bound the analyzers separately from its own
/// workers. A run holds its slot until its child and its output reader have
/// both been reaped. Takes effect for runs that start afterwards; runs
/// already waiting re-check the new limit.
pub fn set_max_concurrent_runs(limit: Option<NonZeroUsize>) {
    SUPERVISOR.gate.set_limit(limit);
}

/// A counting semaphore over rizin runs; see [`set_max_concurrent_runs`].
struct Gate {
    state: Mutex<GateState>,
    changed: Condvar,
}

struct GateState {
    limit: Option<NonZeroUsize>,
    active: usize,
}

impl Gate {
    const fn new() -> Self {
        Self {
            state: Mutex::new(GateState {
                limit: None,
                active: 0,
            }),
            changed: Condvar::new(),
        }
    }

    fn set_limit(&self, limit: Option<NonZeroUsize>) {
        lock(&self.state).limit = limit;
        self.changed.notify_all();
    }

    fn acquire(&self) -> Permit<'_> {
        let mut state = lock(&self.state);
        while state.limit.is_some_and(|limit| state.active >= limit.get()) {
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
        state.active += 1;
        Permit { gate: self }
    }
}

/// One slot of a [`Gate`], released on drop, a panic unwinding included.
struct Permit<'a> {
    gate: &'a Gate,
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        lock(&self.gate.state).active -= 1;
        self.gate.changed.notify_one();
    }
}

/// Cumulative rizin subprocess counters for this process; see [`stats`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Stats {
    /// Recovery runs attempted.
    pub total: u64,
    /// Runs that exited cleanly with well-formed output.
    pub successes: u64,
    /// Runs killed at their wall-clock budget.
    pub timeouts: u64,
    /// Runs that could not be started or supervised, crashed, produced
    /// nothing, or produced output that did not parse in full.
    pub failures: u64,
    /// Runs killed for writing more than the output cap.
    pub output_cap_exceeded: u64,
    /// Stdout readers abandoned; same as [`abandoned_drains`].
    pub abandoned_drains: u64,
}

/// Cumulative rizin subprocess counters for this process.
pub fn stats() -> Stats {
    SUPERVISOR.stats()
}

/// Stdout reader threads abandoned so far. Each one is a permanently parked
/// thread; a long-lived host should surface this on its heartbeat, and rizin
/// turns itself off after eight.
#[must_use]
pub fn abandoned_drains() -> u64 {
    SUPERVISOR.drains_abandoned.load(Ordering::Relaxed)
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

/// The rizin binary, looked up once per process.
fn rizin_binary() -> Option<&'static Path> {
    static CACHED: OnceLock<Option<PathBuf>> = OnceLock::new();
    CACHED
        .get_or_init(|| {
            let found = crate::tools::resolve("rizin");
            match &found {
                Some(path) => tracing::debug!(path = %path.display(), "rizin found"),
                None => tracing::debug!("rizin not found; binary recovery disabled"),
            }
            found
        })
        .as_deref()
}

/// `true` when rizin is available. Cheap — does not spawn anything; only
/// checks the cached lookup.
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
        .get_or_init(|| SUPERVISOR.version_of(rizin_binary()?, VERSION_PROBE_TIMEOUT))
        .as_deref()
}

/// Deadline for the `rizin -v` probe. Measured in milliseconds normally.
const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// More than any version banner; the probe keeps its first line.
const VERSION_PROBE_MAX_OUTPUT: usize = 64 * 1024;

impl Supervisor {
    /// The first line `bin -v` prints, run contained and bounded.
    fn version_of(&self, bin: &Path, timeout: Duration) -> Option<String> {
        let (mut cmd, setup) = rizin_command(bin);
        cmd.arg("-v");
        let RunOutcome::Exited { status, stdout, .. } =
            self.run(cmd, timeout, VERSION_PROBE_MAX_OUTPUT, setup)
        else {
            tracing::warn!(bin = %bin.display(), "rizin version probe did not complete");
            return None;
        };
        let text = String::from_utf8_lossy(&stdout);
        let first = text.lines().next().unwrap_or("").trim();
        if !status.success() || first.is_empty() {
            tracing::warn!(bin = %bin.display(), %status, "rizin version probe failed");
            return None;
        }
        tracing::debug!(version = first, "rizin version");
        Some(first.to_string())
    }
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
/// * the script policy — a change to [`analysis_script`] changes the tables;
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
    // Bump the policy tag whenever `analysis_script` or the tables imported
    // from its output change, so entries recovered under the old policy are
    // not served.
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
    let bin = rizin_binary()?;
    let script = analysis_script(bytes, symbol_count, go_function_metadata);
    SUPERVISOR.recover(bin, bytes, script, settings)
}

/// The memo key for a run: the bytes, the script that will analyse them and
/// the budget, the three things a memoized outcome depends on.
fn memo_key(bytes: &[u8], script: Script, settings: &Settings) -> [u8; 32] {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    for part in [bytes, script.commands.as_bytes()] {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    hasher.update(settings.timeout.as_nanos().to_le_bytes());
    let retry = settings.retry_timeout.map_or(0, |t| t.as_nanos());
    hasher.update(retry.to_le_bytes());
    hasher.finalize().into()
}

/// Most entries the memo holds before it resets.
const MEMO_MAX_ENTRIES: usize = 512;

/// Most rizin output, in bytes, the memo's entries may stand for before it
/// resets. A recovery parsed from up to [`MAX_SUBPROCESS_OUTPUT`] of JSON is
/// itself that order of size, so a count bound alone would let 512 large
/// entries reach many gigabytes.
const MEMO_MAX_BYTES: usize = 256 * 1024 * 1024;

/// Accounting weight of a memoized failure, which holds no tables.
const MEMO_FAILURE_WEIGHT: usize = 64;

/// Recoveries by [`memo_key`], bounded by entry count and by the rizin output
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
        let weight = weight.max(MEMO_FAILURE_WEIGHT);
        if weight > MEMO_MAX_BYTES / 4 {
            tracing::debug!(weight, "rizin memo: entry too large to remember");
            return;
        }
        let map = self
            .map
            .get_or_insert_with(std::collections::HashMap::default);
        if map.len() >= MEMO_MAX_ENTRIES || self.bytes + weight > MEMO_MAX_BYTES {
            tracing::debug!(
                entries = map.len(),
                bytes = self.bytes,
                "rizin memo: full, resetting"
            );
            map.clear();
            self.bytes = 0;
        }
        if map.insert(key, recovery).is_none() {
            self.bytes += weight;
        }
    }
}

/// One recovery attempt, and whether the bytes alone decided its outcome.
#[derive(Clone)]
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
    timed_out: bool,
}

impl Attempt {
    fn decided(recovery: Option<RizinRecovery>, weight: usize) -> Self {
        Self {
            recovery,
            deterministic: true,
            weight,
            timed_out: false,
        }
    }

    fn timed_out() -> Self {
        Self {
            timed_out: true,
            ..Self::decided(None, 0)
        }
    }

    fn transient() -> Self {
        Self {
            recovery: None,
            deterministic: false,
            weight: 0,
            timed_out: false,
        }
    }
}

/// A timeout is the only reason to increase the deadline. Crashes, unsupported
/// formats, output caps and supervision failures do not become long retries.
fn attempt_with_retry(
    timeout: Duration,
    retry_timeout: Option<Duration>,
    mut run: impl FnMut(Duration) -> Attempt,
) -> Attempt {
    let first = run(timeout);
    if first.timed_out
        && let Some(retry) = retry_timeout.filter(|retry| *retry > timeout)
    {
        tracing::info!(
            timeout_secs = retry.as_secs(),
            "retrying timed-out native disassembly"
        );
        run(retry)
    } else {
        first
    }
}

/// Prefix of the temp copies rizin reads its input from.
const TEMP_INPUT_PREFIX: &str = "filefacts-rizin-";

/// A temp copy of an input, deleted on drop, and listed in its supervisor's
/// `temp_inputs` while it lives.
struct TempInput<'s> {
    path: tempfile::TempPath,
    supervisor: &'s Supervisor,
}

impl<'s> TempInput<'s> {
    /// Copy `bytes` to a fresh temp file. `tempfile` creates it with
    /// `O_EXCL`, mode 0600 and a random name, so another local user can
    /// neither predict, pre-create, read nor replace it.
    fn write(supervisor: &'s Supervisor, bytes: &[u8]) -> io::Result<Self> {
        let mut file = tempfile::Builder::new()
            .prefix(TEMP_INPUT_PREFIX)
            .suffix(".bin")
            .tempfile()?;
        file.write_all(bytes)?;
        file.flush()?;
        let path = file.into_temp_path();
        let shutdown = lock(&supervisor.shutdown);
        if *shutdown {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "rizin is shutting down",
            ));
        }
        lock(&supervisor.temp_inputs).push(path.to_path_buf());
        Ok(Self { path, supervisor })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempInput<'_> {
    fn drop(&mut self) {
        let mut inputs = lock(&self.supervisor.temp_inputs);
        if let Some(idx) = inputs.iter().position(|p| p.as_path() == self.path()) {
            inputs.swap_remove(idx);
        }
        // The `TempPath` field deletes the file once this returns.
    }
}

#[cfg(test)]
pub(crate) mod tests;
