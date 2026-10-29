use super::*;
const LOOP: &str = ":1\nset alias=cache\necho 0000>>data\ncopy /b data %alias%\ncopy /b data+%alias%+%alias%\ncopy /b data+data+data\ngoto 1\n";
#[test]
fn snapshot_source_and_backedge_are_bound() {
    let s = analyze(LOOP);
    assert_eq!((s.loops, s.seeded, s.fanout), (1, 1, 2));
    let s = analyze(
        &LOOP
            .replace(":1", ":again!")
            .replace("goto 1", "goto again!"),
    );
    assert_eq!((s.loops, s.seeded), (1, 1));
    let s = analyze(
        &LOOP
            .replace("data", "different.bin")
            .replace("cache", "snapshot.tmp"),
    );
    assert_eq!((s.loops, s.seeded), (1, 1));
}
#[test]
fn unrelated_or_reset_files_do_not_amplify() {
    for s in [
        LOOP.replace("copy /b data %alias%", "copy /b other %alias%"),
        LOOP.replace("goto 1", "goto missing"),
        LOOP.replace("goto 1", "if errorlevel 1 goto 1"),
        LOOP.replace("echo 0000>>data", "echo 0000>data"),
        LOOP.replace(
            "copy /b data+%alias%",
            "echo changed>>%alias%\ncopy /b data+%alias%",
        ),
        LOOP.replace("goto 1", "echo replaced>data\ngoto 1"),
    ] {
        assert_eq!(analyze(&s).loops, 0, "{s}");
    }
}
#[test]
fn dead_or_quoted_loops_do_not_establish_execution() {
    assert_eq!(analyze(&format!("exit /b\n{LOOP}")).loops, 0);
    for prefix in [
        "echo ignored & exit /b",
        "call :stop",
        "other.bat",
        "cmd /c exit",
    ] {
        assert_eq!(
            analyze(&format!("{prefix}\n{LOOP}\n:stop\nexit /b")).loops,
            0
        );
    }
    assert_eq!(
        analyze(&format!("goto done\n{LOOP}\n:done\nexit /b")).loops,
        0
    );
    assert_eq!(
        analyze(
            &LOOP
                .lines()
                .map(|s| format!("rem {s}\n"))
                .collect::<String>()
        )
        .loops,
        0
    );
    assert_eq!(
        analyze(
            &LOOP
                .lines()
                .map(|s| format!("echo {s}\n"))
                .collect::<String>()
        )
        .loops,
        0
    );
}
#[test]
fn empty_or_bounded_profiles_are_distinct() {
    let s = analyze(&LOOP.replace("echo 0000>>data\n", ""));
    assert_eq!((s.loops, s.seeded), (1, 0));
    assert_eq!(analyze(&LOOP.replace("goto 1", "exit /b")).loops, 0);
    assert!(analyze(&"x".repeat(512 * 1024 + 1)).limited);
}
#[test]
fn seed_target_is_bound_to_amplified_source() {
    let s = analyze(&LOOP.replace("echo 0000>>data", "echo 0000>>unrelated"));
    assert_eq!((s.loops, s.seeded), (1, 0));
    let s = analyze(&LOOP.replace(
        "data+%alias%+%alias%",
        "data+%alias%+%alias% separate-output",
    ));
    assert_eq!(s.loops, 0);
}

#[test]
fn redirects_prompts_and_unknown_seed_values_do_not_convict() {
    assert_eq!(
        analyze(&LOOP.replace("set alias=cache", "ctty nul>data\nset alias=cache")).loops,
        0
    );
    assert_eq!(
        analyze(&LOOP.replace("copy /b data %alias%", "copy /b /-y data %alias%")).loops,
        0
    );
    assert_eq!(
        analyze(&LOOP.replace("echo 0000>>data", "echo %unknown%>>data")).seeded,
        0
    );
    assert_ne!(path(r"\\server\data"), path(r"\server\data"));
}

#[test]
fn simple_errorlevel_prelude_reaches_loop() {
    let source = format!("if errorlevel 1 goto start\necho alternate\ngoto start\n:start\n{LOOP}");
    assert_eq!(analyze(&source).seeded, 1);
}
