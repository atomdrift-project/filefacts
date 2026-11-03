//! What remains of filefacts' rizin integration: its settings and
//! process-wide controls, kept so existing hosts still build.
//!
//! filefacts no longer runs rizin. binform recovers the functions, imports,
//! exports and sections of PE, ELF and Mach-O binaries in-process, so every
//! setting here is accepted and ignored, [`available`](crate::rizin::available) is `false`, and the
//! counters stay at zero. The module goes once its hosts stop calling it.

use std::num::NonZeroUsize;
use std::time::Duration;

/// The default of the ignored [`crate::OpenOptions::rizin_timeout`].
pub const DEFAULT_RIZIN_TIMEOUT_SECS: u64 = 600;

/// The rizin settings of one [`crate::ParsedFile`], set through
/// [`crate::OpenOptions`]. None of them changes an extraction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Settings {
    pub(crate) enabled: bool,
    pub(crate) timeout: Duration,
    pub(crate) retry_timeout: Option<Duration>,
    pub(crate) max_bytes: Option<usize>,
    pub(crate) native_arch_only: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout: Duration::from_secs(DEFAULT_RIZIN_TIMEOUT_SECS),
            retry_timeout: None,
            max_bytes: None,
            native_arch_only: false,
        }
    }
}

/// Does nothing: filefacts starts no rizin process.
pub fn kill_all_rizin_groups() {}

/// Does nothing: filefacts starts no rizin process.
pub fn set_max_concurrent_runs(_limit: Option<NonZeroUsize>) {}

/// Cumulative rizin subprocess counters for this process; always zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Stats {
    /// Recovery runs attempted.
    pub total: u64,
    /// Runs that exited cleanly with well-formed output.
    pub successes: u64,
    /// Runs killed at their wall-clock budget.
    pub timeouts: u64,
    /// Runs that could not be started or supervised.
    pub failures: u64,
    /// Runs killed for writing more than the output cap.
    pub output_cap_exceeded: u64,
    /// Stdout readers abandoned.
    pub abandoned_drains: u64,
}

/// Cumulative rizin subprocess counters for this process; always zero.
pub fn stats() -> Stats {
    Stats::default()
}

/// Stdout reader threads abandoned so far; always zero.
#[must_use]
pub fn abandoned_drains() -> u64 {
    0
}

/// Emit binform's recovery statistics as a `tracing::info!` line. Host
/// CLIs call this at shutdown for telemetry.
pub fn log_stats() {
    crate::functions::log_stats();
}

/// `false`: filefacts runs no rizin, installed or not.
pub fn available() -> bool {
    false
}

/// The function-recovery part of the disk-cache key. No rizin setting
/// changes a persisted extraction, so binform's policy is the whole of it.
pub(crate) fn cache_fingerprint(_settings: &Settings) -> String {
    crate::functions::POLICY.to_owned()
}
