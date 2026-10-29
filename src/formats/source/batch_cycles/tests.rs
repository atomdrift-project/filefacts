use super::*;
#[test]
fn binds_arbitrary_labels_and_excludes_forward_and_wait() {
    assert_eq!(
        cycles(":unusual_42\nstart cmd.exe\nstart notepad.exe\ngoto unusual_42\n").0,
        1
    );
    assert_eq!(cycles(":again\nstart\ngoto :again\n").0, 1);
    assert_eq!(
        cycles("goto start\n:start\nstart node.exe\ngoto done\n:done\n").0,
        0
    );
    assert_eq!(cycles(":a\nstart /wait tool.exe\ngoto a\n").0, 0);
    assert_eq!(cycles(":a\nstart tool.exe\ntimeout /t 5\ngoto a\n").0, 0);
    assert_eq!(
        cycles(":a\nstart tool.exe\nif errorlevel 1 exit /b\ngoto a\n").0,
        0
    );
    assert_eq!(cycles(":a\nstart tool.exe\ngoto b\n:b\n").0, 0);
    assert_eq!(cycles(":a\nstart tool.exe & exit\ngoto a\n").0, 0);
    assert_eq!(cycles("exit /b\n:a\nstart tool.exe\ngoto a\n").0, 0);
    assert_eq!(
        cycles("goto done\n:a\nstart tool.exe\ngoto a\n:done\n").0,
        0
    );
    assert_eq!(cycles(":a\nstart %OPTIONS% tool.exe\ngoto a\n").0, 0);
    assert_eq!(
        cycles("if exist flag goto a\n:a\nstart tool.exe\ngoto a\n").0,
        0
    );
    assert_eq!(cycles("goto :eof\n:eof\nstart tool.exe\ngoto eof\n").0, 0);
}

/// A file past the line model's caps reports the analysis limited rather
/// than a clean zero.
#[test]
fn caps_are_reported_not_silent() {
    assert_eq!(cycles(&"x".repeat(512 * 1024 + 1)), (0, true));
    assert_eq!(cycles(&"x\n".repeat(10_001)), (0, true));
    // A duplicate label is ambiguous, not a cap.
    assert_eq!(cycles(":a\nstart x\ngoto a\n:a\n"), (0, false));
    let source = "x\n".repeat(10_001);
    let parsed = crate::OpenOptions::new()
        .file_type(crate::FileType::Batch)
        .open(source.as_bytes());
    assert_eq!(
        parsed.metrics().get("source.batch.cycle_analysis_limited"),
        Some(1.0)
    );
}

/// `if errorlevel N goto L` reaches both of its paths, as in the concat
/// analysis sharing the line model.
#[test]
fn errorlevel_prelude_reaches_the_cycle() {
    assert_eq!(
        cycles("if errorlevel 1 goto a\necho other\n:a\nstart tool.exe\ngoto a\n").0,
        1
    );
}
