//! Crate-wide debug logging.
//!
//! Every extractor that wants to surface a diagnostic — a parse fallback,
//! a structural anomaly, a partial-extraction trigger — routes it through
//! [`log`]. The destination is `stderr`; the gate is the `DEBUG` or
//! `METAPARSE_DEBUG` environment variable.
//!
//! The gate is checked once on first use and cached, so a busy hot path
//! that produces no logs in production pays a single atomic load per
//! call.

use std::fmt;
use std::sync::OnceLock;

static ENABLED: OnceLock<bool> = OnceLock::new();

fn enabled() -> bool {
    *ENABLED.get_or_init(|| {
        std::env::var_os("METAPARSE_DEBUG").is_some() || std::env::var_os("DEBUG").is_some()
    })
}

/// Emit a debug message to stderr if `METAPARSE_DEBUG` or `DEBUG` is set
/// in the environment. Otherwise a no-op.
///
/// Use with `format_args!`:
///
/// ```ignore
/// crate::debug::log(format_args!("pe.authenticode parse failed: {err}"));
/// ```
pub(crate) fn log(args: fmt::Arguments<'_>) {
    if enabled() {
        eprintln!("filefacts: {args}");
    }
}
