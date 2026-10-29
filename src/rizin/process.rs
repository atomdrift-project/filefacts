//! Running one contained rizin subprocess: launch, supervision, output
//! drain, and cleanup on every exit path.

use std::io::{self, Read as _};
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use super::{MAX_ABANDONED_DRAINS, Supervisor, lock};

/// Memory cap on a single rizin subprocess (4 GiB): `RLIMIT_AS` and
/// `RLIMIT_DATA` on Linux, the job's process-memory limit on Windows.
/// Legitimate analysis never approaches it; exceeding it indicates
/// pathological input, and the kernel aborts the subprocess instead of
/// letting it drag the host into OOM.
#[cfg(any(target_os = "linux", windows))]
const MEMORY_LIMIT_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// How long to wait for the stdout drain thread after the child is known dead
/// before abandoning it. The drain normally returns the instant the last write
/// handle closes; this bound exists only so a handle we cannot reach (one an
/// unrelated process inherited through the Windows `CreateProcess` inheritance
/// race, say) degrades to a single lost recovery instead of parking the
/// caller's worker — and everything queued behind it — forever. Generous on
/// purpose: a drain starved by the scheduler under heavy parallel load must
/// never be mistaken for a stuck one.
const DRAIN_GRACE: Duration = Duration::from_secs(60);

/// Poll interval while waiting for a rizin child to exit.
///
/// A plain sleep on purpose: the wait must not run anything else on this
/// thread. A wait that yields to a scheduler hook can be suspended inside a
/// job that never returns, leaving the exited child unreaped and the deadline
/// below — tested only at the loop head — unchecked, while the worker still
/// holds everything its caller held. Parking one worker for the length of a
/// disassembly is the price of a wait loop that cannot be suspended.
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// How a [`Supervisor::run`] child ended.
pub(super) enum RunOutcome {
    /// It exited — on its own, or killed for exceeding the output cap — and
    /// its stdout was read to the end (up to the cap).
    Exited {
        status: ExitStatus,
        stdout: Vec<u8>,
        /// Stdout passed the cap, so the process group was killed and
        /// `stdout` is truncated to the cap.
        cap_hit: bool,
    },
    /// Still running at the deadline: its process group was killed.
    TimedOut,
    /// The run could not be carried out or supervised — shutdown, spawn
    /// refused, no pipe, no reader thread, a wait or read error, or a reader
    /// that had to be abandoned. Says nothing about the input. Logged where
    /// it happens.
    Failed,
}

/// What a drain thread hands back: stdout up to the cap, or the read error.
type Drained = io::Result<Vec<u8>>;

impl Supervisor {
    /// Run `cmd` contained — its own process group with memory and death
    /// limits on Unix, a kill-on-close job on Windows — reading at most `cap`
    /// bytes of stdout and waiting at most `timeout`. stdin and stderr are
    /// null.
    ///
    /// Whatever happens, including a panic unwinding through here, the
    /// child's process group is killed and its leader reaped before this
    /// returns (see [`ChildGuard`]).
    pub(super) fn run(
        &self,
        mut cmd: Command,
        timeout: Duration,
        cap: usize,
        setup: ChildSetup,
    ) -> RunOutcome {
        let _permit = self.gate.acquire();
        let program = Path::new(cmd.get_program()).display().to_string();
        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::null());
        crate::tools::scrub_env(&mut cmd);
        if let Err(error) = apply_unix_hardening(&mut cmd, setup) {
            tracing::warn!(program, %error, "rizin run: cannot contain the child; not starting");
            return RunOutcome::Failed;
        }

        let started = Instant::now();
        let shutdown = lock(&self.shutdown);
        if *shutdown {
            tracing::debug!(program, "rizin run: refused (shutting down)");
            return RunOutcome::Failed;
        }
        // The watchdog shares the child's private group and survives the
        // caller. Its lifeline stays held by ChildGuard through group cleanup
        // and reap.
        #[cfg(any(target_os = "macos", all(test, unix)))]
        let watchdog = {
            #[cfg(test)]
            let enabled = cfg!(target_os = "macos") || matches!(setup, ChildSetup::Watchdog);
            #[cfg(not(test))]
            let enabled = true;
            if enabled {
                match stng_process::Watchdog::arm(&mut cmd, timeout) {
                    Ok(watchdog) => Some(watchdog),
                    Err(error) => {
                        tracing::warn!(program, %error, "rizin run: cannot arm the watchdog; not starting");
                        return RunOutcome::Failed;
                    }
                }
            } else {
                None
            }
        };
        let child = match cmd.spawn() {
            Ok(child) => child,
            Err(error) => {
                tracing::warn!(program, %error, "rizin run: spawn failed");
                return RunOutcome::Failed;
            }
        };
        let mut guard = ChildGuard::new(self, child);
        #[cfg(any(target_os = "macos", all(test, unix)))]
        {
            guard.watchdog = watchdog;
        }
        drop(shutdown);
        // Drop pre-exec captures and their parent-side descriptors promptly.
        drop(cmd);
        let pid = guard.pid;

        // Drain stdout on its own thread while we wait for exit. Without it,
        // `aflj` output on a binary with thousands of functions fills the
        // pipe buffer (~64 KB on macOS), the child blocks on write, and the
        // wait deadlocks.
        let Some(mut stdout) = guard.child.stdout.take() else {
            tracing::warn!(pid, "rizin run: child has no stdout pipe");
            return RunOutcome::Failed;
        };
        let output_cap_hit = Arc::new(AtomicBool::new(false));
        let cap_flag = Arc::clone(&output_cap_hit);
        // The reader keeps at most `cap` bytes; one byte more is the overflow.
        // It then flags it and keeps reading into the void: the child must
        // never block on a full pipe, and the kill that ends it is sent from
        // the supervising loop below, which holds the unreaped leader and so
        // knows the group id is still its own. The buffer comes back over a
        // channel rather than a `JoinHandle` so the wait for it can be bounded
        // (see `join_drain`); the handle itself is dropped, detaching the
        // thread.
        let (drain_tx, drain_rx) = mpsc::sync_channel::<Drained>(1);
        let spawned = std::thread::Builder::new()
            .name("filefacts-rizin-drain".into())
            .spawn(move || {
                let mut buf = Vec::new();
                let limit = u64::try_from(cap).unwrap_or(u64::MAX).saturating_add(1);
                let read = (&mut stdout).take(limit).read_to_end(&mut buf);
                let drained = read.map(|n| {
                    if n > cap {
                        buf.truncate(cap);
                        cap_flag.store(true, Ordering::Release);
                        // Discarded output; an error here only ends the
                        // discarding early.
                        let _ = io::copy(&mut stdout, &mut io::sink());
                    }
                    buf
                });
                // The receiver is gone only when the reader was abandoned.
                let _ = drain_tx.send(drained);
            });
        if let Err(error) = spawned {
            // The closure, and with it the read end, is gone; the guard kills
            // and reaps the child.
            tracing::warn!(pid, %error, "rizin run: cannot start the stdout reader");
            return RunOutcome::Failed;
        }

        // Poll until the configured duration has elapsed. Comparing elapsed
        // time avoids overflowing `Instant` if a caller supplies an
        // intentionally enormous timeout override.
        let mut cap_reported = false;
        loop {
            if !cap_reported && output_cap_hit.load(Ordering::Acquire) {
                cap_reported = true;
                guard.kill_group();
                tracing::warn!(
                    pid,
                    cap_bytes = cap,
                    "rizin output cap exceeded; killing process group"
                );
            }
            match guard.has_exited() {
                Ok(true) => break,
                Ok(false) if started.elapsed() >= timeout => {
                    // Killing the whole group (Unix) / job (Windows) closes
                    // every inherited copy of stdout. Wait — bounded — before
                    // returning so a timed-out analysis does not leave a
                    // reader behind holding output its caller has already
                    // been released from. The output is discarded either way.
                    guard.finish();
                    let _ = self.join_drain(&drain_rx, pid);
                    return RunOutcome::TimedOut;
                }
                Ok(false) => std::thread::sleep(WAIT_POLL_INTERVAL),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    tracing::warn!(pid, %error, "rizin run: waiting for the child failed");
                    guard.finish();
                    let _ = self.join_drain(&drain_rx, pid);
                    return RunOutcome::Failed;
                }
            }
        }
        // The leader has exited, but a helper process could still hold an
        // inherited stdout descriptor open. Kill what remains of the group —
        // and, on Windows, the job — before joining, so neither a descendant
        // nor the reader can retain this caller indefinitely. Where
        // `has_exited` leaves the leader unreaped, its zombie still pins the
        // group id, so the kill cannot reach a recycled group.
        let Some(status) = guard.finish() else {
            tracing::warn!(pid, "rizin run: reaping the child failed");
            let _ = self.join_drain(&drain_rx, pid);
            return RunOutcome::Failed;
        };
        // Wait on every exit-status path—not only success—so a crashing child
        // cannot leave a reader holding a pipe after its caller moves on.
        let stdout = self.join_drain(&drain_rx, pid);
        let cap_hit = output_cap_hit.load(Ordering::Acquire);
        // The watchdog shares this deadline and can kill the group a poll
        // interval before the loop above sees it expire: a leader SIGKILLed
        // past its deadline, not for the cap, timed out.
        if killed_from_outside(status, cap_hit) && started.elapsed() >= timeout {
            return RunOutcome::TimedOut;
        }
        let Some(stdout) = stdout else {
            return RunOutcome::Failed;
        };
        RunOutcome::Exited {
            status,
            stdout,
            cap_hit,
        }
    }

    /// Wait for the stdout drain thread, bounded by [`DRAIN_GRACE`]. `None`
    /// when the read failed or the reader had to be abandoned.
    ///
    /// The reader returns as soon as the last copy of the pipe's write end
    /// closes. Containment (Unix process group / Windows job) closes the
    /// copies we know about; this bound covers the ones we cannot reach —
    /// most plausibly a handle another process inherited through the Windows
    /// `CreateProcess` handle race — so the worst case is one binary analysed
    /// without rizin facts plus a leaked reader thread, never a wedged scan.
    /// The thread is deliberately detached rather than joined on expiry: it
    /// owns the blocked read, and there is no portable way to cancel it.
    fn join_drain(&self, rx: &mpsc::Receiver<Drained>, child_id: u32) -> Option<Vec<u8>> {
        match rx.recv_timeout(DRAIN_GRACE) {
            Ok(Ok(buf)) => Some(buf),
            Ok(Err(error)) => {
                tracing::warn!(pid = child_id, %error, "rizin stdout read failed");
                None
            }
            Err(_) => {
                let abandoned = self.drains_abandoned.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::error!(
                    pid = child_id,
                    grace_s = DRAIN_GRACE.as_secs(),
                    abandoned,
                    "rizin stdout still held open after its process tree exited; \
                     abandoning the reader (a process outside our containment \
                     inherited the pipe). Recovery facts for this binary are lost."
                );
                if abandoned == MAX_ABANDONED_DRAINS {
                    self.disabled.store(true, Ordering::Release);
                    tracing::error!(
                        abandoned,
                        limit = MAX_ABANDONED_DRAINS,
                        "rizin disabled for the rest of this process: too many \
                         abandoned stdout readers, each a leaked thread and buffer"
                    );
                }
                None
            }
        }
    }
}

/// Owns a contained child from spawn to reap. Registered in its supervisor's
/// `pgids` while its group may be live; dropping it unreaped — an early
/// return, a panic unwinding through [`Supervisor::run`] — kills the group
/// and reaps the leader, so no path leaves rizin running unsupervised or as a
/// zombie.
struct ChildGuard<'s> {
    supervisor: &'s Supervisor,
    child: Child,
    pid: u32,
    /// The leader's exit status, once reaped.
    status: Option<ExitStatus>,
    /// [`Self::finish`] has run: the group is dead and out of the registry.
    finished: bool,
    #[cfg(any(target_os = "macos", all(test, unix)))]
    watchdog: Option<stng_process::Watchdog>,
    /// Contains descendants on Windows the way `process_group(0)` does on
    /// Unix. Created immediately after spawn; a helper started in the window
    /// before the assignment lands would escape the job, which is what the
    /// bounded drain join exists to survive.
    #[cfg(windows)]
    job: Option<win_job::Job>,
}

impl<'s> ChildGuard<'s> {
    fn new(supervisor: &'s Supervisor, child: Child) -> Self {
        let pid = child.id();
        #[cfg(windows)]
        let job = {
            use std::os::windows::io::AsRawHandle;
            win_job::Job::containing(child.as_raw_handle().cast())
        };
        lock(&supervisor.pgids).push(pid.cast_signed());
        Self {
            supervisor,
            child,
            pid,
            status: None,
            finished: false,
            #[cfg(any(target_os = "macos", all(test, unix)))]
            watchdog: None,
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
        let pgid = self.pid.cast_signed();
        let mut pgids = lock(&self.supervisor.pgids);
        if let Some(idx) = pgids.iter().position(|&p| p == pgid) {
            pgids.swap_remove(idx);
        }
        drop(pgids);
        // Fallback for platforms without process groups, and for the narrow
        // race where group creation failed before `exec`. Fails harmlessly
        // on a child that has already exited.
        let _ = self.child.kill();
        let status = match self.child.wait() {
            Ok(status) => Some(status),
            Err(error) => {
                tracing::warn!(pid = self.pid, %error, "rizin run: wait failed");
                None
            }
        };
        self.status = self.status.or(status);
        self.status
    }
}

impl Drop for ChildGuard<'_> {
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

/// Whether `status` is a SIGKILL that the output cap does not explain.
#[cfg(unix)]
pub(super) fn killed_from_outside(status: ExitStatus, cap_hit: bool) -> bool {
    use std::os::unix::process::ExitStatusExt;
    !cap_hit && status.signal() == Some(libc::SIGKILL)
}

#[cfg(not(unix))]
pub(super) fn killed_from_outside(_: ExitStatus, _: bool) -> bool {
    false
}

/// How a child is launched, which decides where its limits are applied.
#[derive(Clone, Copy)]
pub(super) enum ChildSetup {
    /// Spawned directly; on Linux a pre-exec hook applies the limits.
    Native,
    /// [`Self::Native`] with the macOS watchdog armed, on any Unix.
    #[cfg(all(test, unix))]
    Watchdog,
    /// Spawned through [`LinuxLauncher`], which applies the limits by exec.
    #[cfg(target_os = "linux")]
    ExternalLinux,
}

/// The command for running `bin`, and how it launches.
///
/// A large Linux caller launches through [`LinuxLauncher`], so the fork that
/// a pre-exec hook forces does not copy its page tables just to exec a small
/// helper. Small callers keep the native path: the extra execs cost more than
/// they save there. Missing or incompatible utilities also keep it.
pub(super) fn rizin_command(bin: &Path) -> (Command, ChildSetup) {
    #[cfg(target_os = "linux")]
    if large_linux_parent()
        && let Some(launcher) = linux_launcher()
        && let Some(cmd) = launcher.command(bin)
    {
        return (cmd, ChildSetup::ExternalLinux);
    }
    (Command::new(bin), ChildSetup::Native)
}

#[cfg(target_os = "linux")]
fn large_linux_parent() -> bool {
    std::fs::read_to_string("/proc/self/status").is_ok_and(|status| {
        status.lines().any(|line| {
            line.strip_prefix("VmRSS:")
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse::<u64>().ok())
                .is_some_and(|kib| kib >= 512 * 1024)
        })
    })
}

/// The memory limits a contained child gets: this process's own limits,
/// each lowered to [`MEMORY_LIMIT_BYTES`] and never raised, so a caller that
/// is already tighter stays tighter — soft limit included.
///
/// Read in the parent, which keeps all allocation and formatting out of a
/// pre-exec hook.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct MemoryLimits {
    address_space: libc::rlimit,
    data: libc::rlimit,
}

#[cfg(target_os = "linux")]
impl MemoryLimits {
    fn inherited() -> io::Result<Self> {
        let capped = |resource| {
            let mut limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: `limit` is writable storage for the requested resource.
            #[allow(unsafe_code)]
            if unsafe { libc::getrlimit(resource, &raw mut limit) } != 0 {
                return Err(io::Error::last_os_error());
            }
            let cap = MEMORY_LIMIT_BYTES as libc::rlim_t;
            Ok(libc::rlimit {
                rlim_cur: limit.rlim_cur.min(cap),
                rlim_max: limit.rlim_max.min(cap),
            })
        };
        Ok(Self {
            address_space: capped(libc::RLIMIT_AS)?,
            data: capped(libc::RLIMIT_DATA)?,
        })
    }
}

/// `setpriv`, `prlimit` and `/bin/sh`, which together give an exec'd child
/// the containment [`apply_unix_hardening`]'s hook would, without a fork of
/// the large parent running Rust code.
#[cfg(target_os = "linux")]
struct LinuxLauncher {
    setpriv: PathBuf,
    prlimit: PathBuf,
}

/// The launcher's shell. A fixed path, not a `PATH` lookup: the shell runs
/// before any limit is in place.
#[cfg(target_os = "linux")]
const LAUNCHER_SHELL: &str = "/bin/sh";

#[cfg(target_os = "linux")]
impl LinuxLauncher {
    fn command(&self, bin: &Path) -> Option<Command> {
        let limits = match MemoryLimits::inherited() {
            Ok(limits) => limits,
            Err(error) => {
                tracing::warn!(%error, "rizin launcher: cannot read inherited limits");
                return None;
            }
        };
        let spec = |limit: libc::rlimit| format!("{}:{}", limit.rlim_cur, limit.rlim_max);
        let mut cmd = Command::new(&self.setpriv);
        cmd.args(["--pdeathsig", "KILL", "--", LAUNCHER_SHELL])
            .args([
                "-c",
                // setpriv arms PDEATHSIG before this check. A parent that
                // died before it was armed has already changed PPID; after
                // arming, the kernel kills us. Every stage execs in place,
                // retaining the child PID and private process group.
                "[ \"$PPID\" -eq \"$1\" ] || exit 1; shift; exec \"$@\"",
                "filefacts-rizin",
            ])
            .arg(std::process::id().to_string())
            .arg(&self.prlimit)
            .arg(format!("--as={}", spec(limits.address_space)))
            .arg(format!("--data={}", spec(limits.data)))
            .arg("--")
            .arg(bin);
        Some(cmd)
    }
}

#[cfg(target_os = "linux")]
fn linux_launcher() -> Option<&'static LinuxLauncher> {
    static LAUNCHER: std::sync::OnceLock<Option<LinuxLauncher>> = std::sync::OnceLock::new();
    LAUNCHER
        .get_or_init(|| {
            let (Some(setpriv), Some(prlimit)) = (
                crate::tools::resolve("setpriv"),
                crate::tools::resolve("prlimit"),
            ) else {
                tracing::debug!(
                    "rizin launcher: setpriv or prlimit not found; using the native path"
                );
                return None;
            };
            let launcher = LinuxLauncher { setpriv, prlimit };
            // Check the complete utility chain once, with a bounded trusted
            // no-op. Older setpriv versions lack --pdeathsig. A refusal falls
            // back to the native hook, never to an uncontained Rizin process.
            let mut probe = launcher.command(Path::new(LAUNCHER_SHELL))?;
            probe.args(["-c", "exit 0"]);
            match super::SUPERVISOR.run(
                probe,
                Duration::from_secs(2),
                64 * 1024,
                ChildSetup::ExternalLinux,
            ) {
                RunOutcome::Exited {
                    status,
                    cap_hit: false,
                    ..
                } if status.success() => {
                    tracing::info!("Rizin exec launcher available for large Linux callers");
                    Some(launcher)
                }
                _ => {
                    tracing::debug!("rizin launcher: probe failed; using the native path");
                    None
                }
            }
        })
        .as_ref()
}

/// Apply Unix subprocess hardening: an own process group everywhere, plus
/// the Linux memory and parent-death limits on the native launch path.
///
/// Any `pre_exec` hook forces Rust's `Command` off its `posix_spawn` path and
/// through `fork()`, which in a large multithreaded jemalloc process means
/// taking every allocator prefork lock. So this hook is installed only on
/// Linux, the one platform where it enforces something: macOS rejects the
/// 4 GiB `RLIMIT_DATA` with `EINVAL` (see the module docs) and gets its
/// parent-death guard from the watchdog's own hook, and the BSDs have no
/// parent-death signal. Elsewhere `process_group(0)` alone keeps the
/// `posix_spawn` path.
#[cfg(unix)]
#[cfg_attr(
    not(target_os = "linux"),
    expect(
        clippy::unnecessary_wraps,
        reason = "only the Linux limits can fail to be read"
    )
)]
fn apply_unix_hardening(cmd: &mut Command, setup: ChildSetup) -> io::Result<()> {
    use std::os::unix::process::CommandExt;
    cmd.process_group(0);
    #[cfg(target_os = "linux")]
    {
        if matches!(setup, ChildSetup::ExternalLinux) {
            return Ok(());
        }
        let limits = MemoryLimits::inherited()?;
        // Read before the fork: the child compares it with `getppid()`.
        let parent = std::process::id() as libc::pid_t;
        // SAFETY: the hook runs in the forked child between `fork()` and
        // `exec()`, where only async-signal-safe work is sound — no
        // allocation, no locks. `getppid` and `_exit` are on POSIX's
        // async-signal-safe list. `setrlimit` and `prctl` are not listed, but
        // glibc and musl implement both as bare system calls that neither
        // allocate nor lock. `io::Error::last_os_error` wraps the raw errno
        // without allocating. `limits` is plain data copied into the closure.
        #[allow(unsafe_code)]
        unsafe {
            cmd.pre_exec(move || {
                // Only ever lowers: the values are the inherited limits
                // capped, so the kernel accepts them, and a failure means the
                // child would run unlimited — refuse instead.
                for (resource, limit) in [
                    (libc::RLIMIT_AS, &limits.address_space),
                    (libc::RLIMIT_DATA, &limits.data),
                ] {
                    if libc::setrlimit(resource, limit) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
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
                Ok(())
            });
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = setup;
    Ok(())
}

#[cfg(not(unix))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "shares the Unix signature, where hardening can fail"
)]
fn apply_unix_hardening(_: &mut Command, _: ChildSetup) -> io::Result<()> {
    Ok(())
}

/// Windows analogue of the Unix private process group: a Job Object holding
/// the rizin leader and everything it spawns.
///
/// Unix hardening puts rizin in its own process group so a single `kill(-pgid)`
/// reaps descendants; without an equivalent, a helper that inherited rizin's
/// stdout keeps the pipe's write end open after the leader exits, `read_to_end`
/// never returns, and the worker blocked on the drain join is retained until
/// [`DRAIN_GRACE`]. `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` also makes the
/// cleanup unconditional: whatever is still in the job dies when the handle
/// closes, including on a panic unwind. `JOB_OBJECT_LIMIT_PROCESS_MEMORY`
/// applies [`MEMORY_LIMIT_BYTES`] to each process in the job.
///
/// Addressing the job (not a pid) is what makes this safe to use *after* the
/// leader has been reaped — a pid can be recycled the moment it is waited on,
/// a job handle cannot.
#[cfg(windows)]
#[allow(unsafe_code)] // FFI to kernel32 job-object APIs; each call site documents its invariants.
mod win_job {
    use std::ffi::c_void;

    const JOB_OBJECT_LIMIT_PROCESS_MEMORY: u32 = 0x0100;
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
        /// Create a kill-on-close, memory-limited job and put `process` in
        /// it. `None` when any step fails, logged — the bounded drain join is
        /// then the backstop.
        pub(super) fn containing(process: *mut c_void) -> Option<Self> {
            // SAFETY: null attributes/name request an unnamed default job;
            // the returned handle is checked before use and owned by `Job`.
            let job = unsafe { CreateJobObjectW(std::ptr::null_mut(), std::ptr::null()) };
            if job.is_null() {
                let error = std::io::Error::last_os_error();
                tracing::warn!(%error, "rizin job: CreateJobObjectW failed");
                return None;
            }
            let job = Self(job);
            let mut info = ExtendedLimitInformation::default();
            info.basic.limit_flags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
            info.process_memory_limit =
                usize::try_from(super::MEMORY_LIMIT_BYTES).unwrap_or(usize::MAX);
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
            if set == 0 {
                let error = std::io::Error::last_os_error();
                tracing::warn!(%error, "rizin job: SetInformationJobObject failed");
                return None;
            }
            // SAFETY: both handles are live; failure is checked below.
            if unsafe { AssignProcessToJobObject(job.0, process) } == 0 {
                let error = std::io::Error::last_os_error();
                tracing::warn!(%error, "rizin job: AssignProcessToJobObject failed");
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

/// SIGKILL the process group led by `child_id`. Called by [`ChildGuard`]
/// while the leader is still unreaped, so the id is still its own, and by
/// the shutdown reaper under the registry lock. No-op on non-Unix.
#[cfg_attr(not(unix), allow(unused_variables))]
pub(super) fn kill_process_group(child_id: u32) {
    #[cfg(unix)]
    // SAFETY: libc::kill with negative pid targets the process group.
    // Tolerates already-dead groups (ESRCH) silently.
    #[allow(unsafe_code)]
    unsafe {
        libc::kill(-(child_id as libc::pid_t), libc::SIGKILL);
    }
}

#[cfg(test)]
mod tests;
