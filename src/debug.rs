//! Crate-wide debug logging.
//!
//! Every extractor that wants to surface a diagnostic — a parse fallback,
//! a structural anomaly, a partial-extraction trigger — routes it through
//! [`log`], which emits a `tracing` event at `DEBUG` level with target
//! `filefacts::debug`. The library never writes to stderr itself: what is
//! shown, and where, is the host's choice of `tracing` subscriber. The
//! `filefacts` CLI installs one on stderr when `FILEFACTS_DEBUG` is set.
//!
//! `tracing` checks whether the event is enabled before formatting it, so a
//! hot path with no subscriber interested pays a cached interest check per
//! call.

use std::fmt;

/// Emit a debug diagnostic through `tracing`.
///
/// Use with `format_args!`:
///
/// ```ignore
/// crate::debug::log(format_args!("pe.authenticode parse failed: {err}"));
/// ```
pub(crate) fn log(args: fmt::Arguments<'_>) {
    tracing::debug!(target: "filefacts::debug", "{args}");
}
