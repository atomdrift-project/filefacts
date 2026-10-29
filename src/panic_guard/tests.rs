use super::*;

#[test]
fn catch_infallible_handles_clean_value() {
    assert_eq!(catch_infallible(|| "ok"), Ok("ok"));
}

#[test]
fn catch_infallible_catches_lazy_walker_panic() {
    let result: Result<(), String> = catch_infallible(|| panic!("walker tripped"));
    match result {
        Err(msg) => assert!(msg.contains("walker tripped")),
        other => panic!("expected a caught panic, got {other:?}"),
    }
}

/// A guard nested inside another must hand suppression back to the outer
/// one: resetting the flag to `false` would let the outer closure's later
/// panics reach the user's hook.
#[test]
fn nested_guards_restore_the_outer_suppression() {
    let flag = || SUPPRESS_PANIC_OUTPUT.with(Cell::get);
    assert!(!flag());
    let outer = catch_infallible(|| {
        let inner: Result<(), String> = catch_infallible(|| panic!("inner"));
        assert!(inner.is_err());
        flag()
    });
    assert_eq!(outer, Ok(true));
    assert!(!flag(), "the outermost guard clears it again");
}
