//! Turning a panic in parse code into an error, without the panic hook
//! printing it.
//!
//! Parsers of untrusted bytes, filefacts' own and its dependencies', can
//! panic on hostile input. Every stage runs inside [`catch_infallible`],
//! which unwinds the panic into the message it carried. The expected panic is
//! kept off stderr by a hook that stays silent only while its thread is
//! inside a guard.

use std::cell::Cell;
use std::panic;
use std::sync::Once;

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

// Every guard in filefacts (this one, goblin_safe's, and the per-stage
// guards in `lib.rs`) turns a
// parser panic into a recorded error by unwinding. Under `panic = "abort"`
// `catch_unwind` catches nothing and one malformed file kills the host
// process, so refuse to build that way rather than silently lose the
// guarantee.
#[cfg(panic = "abort")]
compile_error!(
    "filefacts requires `panic = \"unwind\"`: hostile inputs make its parsers panic, and \
     those panics are caught with `catch_unwind` and reported as errors. With \
     `panic = \"abort\"` a single malformed file would abort the whole process."
);

thread_local! {
    static SUPPRESS_PANIC_OUTPUT: Cell<bool> = const { Cell::new(false) };
}

/// Install a process-wide panic hook (once) that swallows panic
/// messages from threads that opted into suppression. One install, never
/// swapped, so concurrent guards need no lock.
///
/// This is deliberately process-global — a panic hook cannot be anything
/// else — but it is installed at most once and only filters: it chains to
/// whatever hook was installed before it (the host's, or std's default), and
/// silences a panic only while the panicking thread is inside a guard. Panics anywhere else reach the previous hook untouched.
/// A host that installs its own hook *after* filefacts' first parse replaces
/// this one, which costs only the suppression of expected parser panics.
fn install_suppression_hook() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            if SUPPRESS_PANIC_OUTPUT.with(Cell::get) {
                return;
            }
            previous(info);
        }));
    });
}

fn run<T, F>(f: F) -> std::thread::Result<T>
where
    F: FnOnce() -> T,
{
    install_suppression_hook();

    /// Puts back the flag as the guard found it, so a guard nested inside
    /// another leaves the outer one still suppressing when it returns.
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            SUPPRESS_PANIC_OUTPUT.with(|flag| flag.set(self.0));
        }
    }

    let _restore = Restore(SUPPRESS_PANIC_OUTPUT.with(|flag| flag.replace(true)));
    panic::catch_unwind(panic::AssertUnwindSafe(f))
}

/// Catch panics around an infallible call (a lazy goblin walk, or any
/// other parse of untrusted bytes), returning the panic's message as the error.
pub(crate) fn catch_infallible<T, F>(f: F) -> Result<T, String>
where
    F: FnOnce() -> T,
{
    run(f).map_err(|payload| panic_message(&*payload))
}

#[cfg(test)]
mod tests;
