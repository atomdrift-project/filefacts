//! Crate-wide debug logging.
//!
//! Every extractor that wants to surface a diagnostic — a parse fallback,
//! a structural anomaly, a partial-extraction trigger — routes it through
//! [`log`]. The destination is `stderr`; the gate is the
//! `FILEFACTS_DEBUG` environment variable (any value except empty, `0` or
//! `false`). The generic `DEBUG` is deliberately not honoured: it is
//! commonly set for other tools (node's `debug` package reads it), and a
//! library must not start writing to a host's stderr because of it.
//!
//! The gate is checked once on first use and cached, so a busy hot path
//! that produces no logs in production pays a single atomic load per
//! call.

use std::ffi::OsString;
use std::fmt;
use std::sync::OnceLock;

static ENABLED: OnceLock<bool> = OnceLock::new();

fn enabled() -> bool {
    *ENABLED.get_or_init(|| enabled_in(|name| std::env::var_os(name)))
}

/// The gate, reading variables through `var` so tests need not touch the
/// process environment.
fn enabled_in(var: impl Fn(&str) -> Option<OsString>) -> bool {
    var("FILEFACTS_DEBUG")
        .is_some_and(|v| !(v.is_empty() || v == "0" || v.eq_ignore_ascii_case("false")))
}

/// Emit a debug message to stderr if `FILEFACTS_DEBUG` is set in the
/// environment. Otherwise a no-op.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn env_with(name: &'static str, value: &'static str) -> impl Fn(&str) -> Option<OsString> {
        move |var| (var == name).then(|| OsString::from(value))
    }

    #[test]
    fn only_the_filefacts_variable_enables_logging() {
        assert!(enabled_in(env_with("FILEFACTS_DEBUG", "1")));
        // Commonly set for other tools; must not make the library chatty.
        assert!(!enabled_in(env_with("DEBUG", "*")));
        assert!(!enabled_in(env_with("METAPARSE_DEBUG", "1")));
        assert!(!enabled_in(|_| None));
    }

    #[test]
    fn explicit_off_values_disable_logging() {
        for off in ["", "0", "false", "FALSE"] {
            assert!(!enabled_in(env_with("FILEFACTS_DEBUG", off)), "{off:?}");
        }
    }
}
